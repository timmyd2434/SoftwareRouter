package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
)

// validateStaticRoute checks if a static route is safe to apply.
// It verifies the gateway is on a directly-connected subnet and
// prevents dangerous default route overrides.
func validateStaticRoute(destination, gateway string) error {
	gatewayIP := net.ParseIP(gateway)
	if gatewayIP == nil {
		return fmt.Errorf("invalid gateway IP: %s", gateway)
	}

	// Block default route override (0.0.0.0/0) — this would replace the
	// system's entire default route and blackhole all traffic if the
	// gateway is unreachable or incorrect.
	if destination == "0.0.0.0/0" || destination == "::/0" {
		return fmt.Errorf("cannot add a default route (0.0.0.0/0 or ::/0) via static routes — " +
			"this would override the system's default gateway and could blackhole all traffic. " +
			"Use the Multi-WAN configuration to manage default routes instead")
	}

	// Check if the gateway is on a directly-connected subnet.
	// A route pointing to a gateway that isn't reachable via any local
	// interface will silently blackhole all traffic matching that destination.
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Warning: could not enumerate interfaces for route validation: %v", err)
		return nil // Don't block on enumeration failure
	}

	gatewayReachable := false
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.Contains(gatewayIP) {
				gatewayReachable = true
				break
			}
		}
		if gatewayReachable {
			break
		}
	}

	if !gatewayReachable {
		return fmt.Errorf("gateway %s is not on any directly-connected subnet — "+
			"traffic matching this route will be blackholed because the gateway is unreachable", gateway)
	}

	return nil
}

// StaticRoute represents a user-defined static route
type StaticRoute struct {
	ID          string `json:"id"`
	Destination string `json:"destination"` // CIDR (e.g., 10.0.0.0/24)
	Gateway     string `json:"gateway"`     // Next hop IP
	Metric      int    `json:"metric"`
	Comment     string `json:"comment"`
}

// RouteStore manages persistence
type RouteStore struct {
	Routes []StaticRoute `json:"routes"`
}

var (
	routeStore       RouteStore
	routeStoreLock   sync.RWMutex
	routesConfigPath = "/etc/softrouter/routes.json"
)

func initRoutes() {
	loadRoutes()
	applyRoutes()
}

func loadRoutes() {
	routeStoreLock.Lock()
	defer routeStoreLock.Unlock()

	data, err := os.ReadFile(routesConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			routeStore.Routes = []StaticRoute{}
			return
		}
		fmt.Printf("Error loading routes: %v\n", err)
		return
	}

	if err := json.Unmarshal(data, &routeStore); err != nil {
		fmt.Printf("Error parsing routes: %v\n", err)
		routeStore.Routes = []StaticRoute{}
	}
}

func saveRoutes() error {
	routeStoreLock.RLock()
	data, err := json.MarshalIndent(routeStore, "", "  ")
	routeStoreLock.RUnlock()

	if err != nil {
		return err
	}
	return os.WriteFile(routesConfigPath, data, 0600)
}

// applyRoutes applies all routes to the system
// To be safe and idempotent, we might want to flush user-added routes or check existence.
// For simplicity in this `ip route` wrapper, we try to add and ignore "exists" errors,
// or we could use netlink. For generic reliability without complex libraries, we'll try to sync.
func applyRoutes() {
	routeStoreLock.RLock()
	routes := routeStore.Routes
	routeStoreLock.RUnlock()

	fmt.Println("Applying Static Routes...")

	for _, route := range routes {
		// ip route replace <dest> via <gateway> metric <metric>
		// "replace" is idempotent-ish (will update if changed, add if new)
		args := []string{"route", "replace", route.Destination, "via", route.Gateway}
		if route.Metric > 0 {
			args = append(args, "metric", fmt.Sprintf("%d", route.Metric))
		}

		if out, err := runPrivilegedCombinedOutput("ip", args...); err != nil {
			fmt.Printf("Failed to apply route %s: %v (%s)\n", route.Destination, err, string(out))
		} else {
			fmt.Printf("Applied route: %s via %s\n", route.Destination, route.Gateway)
		}
	}
}

// deleteSystemRoute removes the route from kernel
func deleteSystemRoute(route StaticRoute) error {
	// ip route del <dest> via <gateway>
	// We ignore errors if route doesn't exist to allow cleanup of stale db entries
	return runPrivileged("ip", "route", "del", route.Destination, "via", route.Gateway)
}

// --- Handlers ---

func getRoutes(w http.ResponseWriter, r *http.Request) {
	routeStoreLock.RLock()
	routes := routeStore.Routes
	routeStoreLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(routes)
}

func createRoute(w http.ResponseWriter, r *http.Request) {
	var req StaticRoute
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Destination == "" || req.Gateway == "" {
		http.Error(w, "Destination and Gateway are required", http.StatusBadRequest)
		return
	}

	// Validate destination as a valid CIDR
	if _, _, err := net.ParseCIDR(req.Destination); err != nil {
		http.Error(w, "Destination must be a valid CIDR (e.g., 10.0.0.0/24)", http.StatusBadRequest)
		return
	}

	// Validate gateway as a valid IP
	if net.ParseIP(req.Gateway) == nil {
		http.Error(w, "Gateway must be a valid IP address", http.StatusBadRequest)
		return
	}

	// Validate the route is safe to apply (gateway reachable, no default route override)
	if err := validateStaticRoute(req.Destination, req.Gateway); err != nil {
		respondInvalidRequest(w, "Route validation failed")
		return
	}

	// Generate ID if missing
	if req.ID == "" {
		req.ID = fmt.Sprintf("rt-%d", len(routeStore.Routes)+1) // Simple ID strategy
	}

	routeStoreLock.Lock()
	routeStore.Routes = append(routeStore.Routes, req)
	routeStoreLock.Unlock()

	if err := saveRoutes(); err != nil {
		http.Error(w, "Failed to save route", http.StatusInternalServerError)
		return
	}

	// Apply immediately
	// Note: In production we should handle rollback if apply fails
	applyRoutes()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(req)
}

func deleteRoute(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}

	routeStoreLock.Lock()
	var newRoutes []StaticRoute
	var targetRoute *StaticRoute

	for _, rt := range routeStore.Routes {
		if rt.ID == id {
			// Found it, keep reference to delete from system
			r := rt
			targetRoute = &r
			continue
		}
		newRoutes = append(newRoutes, rt)
	}

	if targetRoute == nil {
		routeStoreLock.Unlock()
		http.Error(w, "Route not found", http.StatusNotFound)
		return
	}

	routeStore.Routes = newRoutes
	routeStoreLock.Unlock()

	// Persistence
	saveRoutes()

	// Remove from system
	if err := deleteSystemRoute(*targetRoute); err != nil {
		fmt.Printf("Warning: Failed to delete kernel route: %v\n", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}
