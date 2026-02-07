import React, { useState, useEffect } from 'react';
import { Modal, Button, Form, Alert, Spinner, Card } from 'react-bootstrap';
import './SetupWizard.css';

export default function SetupWizard({ show, onComplete }) {
    const [interfaces, setInterfaces] = useState([]);
    const [selectedWAN, setSelectedWAN] = useState('');
    const [selectedLANs, setSelectedLANs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        if (show) {
            fetchInterfaces();
        }
    }, [show]);

    const fetchInterfaces = async () => {
        try {
            const token = localStorage.getItem('sr_token');
            const response = await fetch('/api/interfaces', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) throw new Error('Failed to fetch interfaces');

            const data = await response.json();
            setInterfaces(data.interfaces || []);
            setLoading(false);
        } catch (err) {
            setError(err.message);
            setLoading(false);
        }
    };

    const handleComplete = async () => {
        if (!selectedWAN) {
            setError('Please select a WAN interface');
            return;
        }

        if (selectedLANs.length === 0) {
            setError('Please select at least one LAN interface');
            return;
        }

        try {
            setLoading(true);
            const token = localStorage.getItem('sr_token');

            // Get CSRF token
            const csrfResponse = await fetch('/api/csrf-token', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const csrfData = await csrfResponse.json();

            // Build updates array
            const updates = interfaces.map(iface => {
                let label = 'None';
                if (iface.name === selectedWAN) label = 'WAN';
                if (selectedLANs.includes(iface.name)) label = 'LAN';

                return {
                    interface: iface.name,
                    label: label
                };
            });

            // Apply configuration
            const response = await fetch('/api/interface/metadata/bulk', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfData.token
                },
                body: JSON.stringify({ updates })
            });

            if (!response.ok) throw new Error('Failed to save configuration');

            setLoading(false);
            onComplete();
        } catch (err) {
            setError(err.message);
            setLoading(false);
        }
    };

    const upInterfaces = interfaces.filter(i => i.state === 'UP');
    const availableLANs = upInterfaces.filter(i => i.name !== selectedWAN);

    return (
        <Modal show={show} backdrop="static" keyboard={false} size="lg" centered>
            <Modal.Header className="setup-wizard-header">
                <Modal.Title>
                    <i className="bi bi-router me-2"></i>
                    Initial Setup Wizard
                </Modal.Title>
            </Modal.Header>
            <Modal.Body>
                {loading && !interfaces.length ? (
                    <div className="text-center py-5">
                        <Spinner animation="border" variant="primary" />
                        <p className="mt-3">Loading network interfaces...</p>
                    </div>
                ) : (
                    <>
                        <Alert variant="info" className="d-flex align-items-start">
                            <i className="bi bi-info-circle-fill me-2 mt-1"></i>
                            <div>
                                <strong>Welcome to SoftRouter!</strong>
                                <br />
                                Please identify your WAN (internet) and LAN (internal network) interfaces.
                                This is required to configure firewall rules correctly.
                            </div>
                        </Alert>

                        {error && (
                            <Alert variant="danger" onClose={() => setError('')} dismissible>
                                <i className="bi bi-exclamation-triangle-fill me-2"></i>
                                {error}
                            </Alert>
                        )}

                        <Card className="mb-4">
                            <Card.Header className="bg-primary text-white">
                                <i className="bi bi-globe me-2"></i>
                                <strong>Step 1:</strong> Select WAN Interface (Internet Connection)
                            </Card.Header>
                            <Card.Body>
                                {upInterfaces.length === 0 ? (
                                    <Alert variant="warning">
                                        No active interfaces found. Please ensure at least one interface is connected.
                                    </Alert>
                                ) : (
                                    <Form.Group>
                                        {upInterfaces.map(iface => (
                                            <Form.Check
                                                key={iface.name}
                                                type="radio"
                                                id={`wan-${iface.name}`}
                                                name="wan"
                                                label={
                                                    <div className="d-flex justify-content-between align-items-center w-100">
                                                        <div>
                                                            <strong>{iface.name}</strong>
                                                            {iface.ipv4 && <span className="text-muted ms-2">({iface.ipv4})</span>}
                                                        </div>
                                                        <small className="text-muted">{iface.mac}</small>
                                                    </div>
                                                }
                                                value={iface.name}
                                                checked={selectedWAN === iface.name}
                                                onChange={(e) => {
                                                    setSelectedWAN(e.target.value);
                                                    // Remove from LANs if was selected
                                                    setSelectedLANs(selectedLANs.filter(n => n !== e.target.value));
                                                }}
                                                className="interface-radio"
                                            />
                                        ))}
                                    </Form.Group>
                                )}
                            </Card.Body>
                        </Card>

                        <Card>
                            <Card.Header className="bg-success text-white">
                                <i className="bi bi-hdd-network me-2"></i>
                                <strong>Step 2:</strong> Select LAN Interfaces (Internal Network)
                            </Card.Header>
                            <Card.Body>
                                {!selectedWAN ? (
                                    <Alert variant="info">
                                        <i className="bi bi-arrow-up me-2"></i>
                                        Please select a WAN interface first
                                    </Alert>
                                ) : availableLANs.length === 0 ? (
                                    <Alert variant="warning">
                                        No additional interfaces available for LAN
                                    </Alert>
                                ) : (
                                    <Form.Group>
                                        {availableLANs.map(iface => (
                                            <Form.Check
                                                key={iface.name}
                                                type="checkbox"
                                                id={`lan-${iface.name}`}
                                                label={
                                                    <div className="d-flex justify-content-between align-items-center w-100">
                                                        <div>
                                                            <strong>{iface.name}</strong>
                                                            {iface.ipv4 && <span className="text-muted ms-2">({iface.ipv4})</span>}
                                                        </div>
                                                        <small className="text-muted">{iface.mac}</small>
                                                    </div>
                                                }
                                                value={iface.name}
                                                checked={selectedLANs.includes(iface.name)}
                                                onChange={(e) => {
                                                    if (e.target.checked) {
                                                        setSelectedLANs([...selectedLANs, iface.name]);
                                                    } else {
                                                        setSelectedLANs(selectedLANs.filter(n => n !== iface.name));
                                                    }
                                                }}
                                                className="interface-checkbox"
                                            />
                                        ))}
                                    </Form.Group>
                                )}
                            </Card.Body>
                        </Card>

                        {selectedWAN && selectedLANs.length > 0 && (
                            <Alert variant="success" className="mt-3">
                                <i className="bi bi-check-circle-fill me-2"></i>
                                <strong>Configuration Summary:</strong>
                                <ul className="mb-0 mt-2">
                                    <li><strong>WAN:</strong> {selectedWAN}</li>
                                    <li><strong>LAN:</strong> {selectedLANs.join(', ')}</li>
                                </ul>
                            </Alert>
                        )}
                    </>
                )}
            </Modal.Body>
            <Modal.Footer>
                <Button
                    variant="primary"
                    size="lg"
                    onClick={handleComplete}
                    disabled={!selectedWAN || selectedLANs.length === 0 || loading}
                    className="w-100"
                >
                    {loading ? (
                        <>
                            <Spinner animation="border" size="sm" className="me-2" />
                            Applying Configuration...
                        </>
                    ) : (
                        <>
                            <i className="bi bi-check-lg me-2"></i>
                            Complete Setup
                        </>
                    )}
                </Button>
            </Modal.Footer>
        </Modal>
    );
}
