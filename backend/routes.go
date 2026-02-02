package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
)

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
	return os.WriteFile(routesConfigPath, data, 0644)
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
