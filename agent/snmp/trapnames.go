package snmp

// trapNames names the common standard traps (RFC 3418, RFC 2863, RFC 1657, RFC 4750, RFC 1628);
// unknown OIDs keep only their number. Vendor traps get names, severities and varbind names from
// the trap profiles (trapprofile.go), built in or compiled from MIBs with `wtctl mib compile`.
var trapNames = map[string]string{
	"1.3.6.1.6.3.1.1.5.1":   "coldStart",
	"1.3.6.1.6.3.1.1.5.2":   "warmStart",
	"1.3.6.1.6.3.1.1.5.3":   "linkDown",
	"1.3.6.1.6.3.1.1.5.4":   "linkUp",
	"1.3.6.1.6.3.1.1.5.5":   "authenticationFailure",
	"1.3.6.1.6.3.1.1.5.6":   "egpNeighborLoss",
	"1.3.6.1.2.1.14.16.2.1": "ospfIfStateChange",
	"1.3.6.1.2.1.14.16.2.2": "ospfNbrStateChange",
	"1.3.6.1.2.1.15.7.1":    "bgpEstablished",
	"1.3.6.1.2.1.15.7.2":    "bgpBackwardTransition",
	"1.3.6.1.2.1.17.0.1":    "newRoot",
	"1.3.6.1.2.1.17.0.2":    "topologyChange",
	"1.3.6.1.2.1.33.2.1":    "upsTrapOnBattery",
	"1.3.6.1.2.1.33.2.2":    "upsTrapTestCompleted",
	"1.3.6.1.2.1.33.2.3":    "upsTrapAlarmEntryAdded",
	"1.3.6.1.2.1.33.2.4":    "upsTrapAlarmEntryRemoved",
	"1.3.6.1.2.1.47.2.0.1":  "entConfigChange",
}

// TrapName returns the symbolic name of a trap OID, or "" when unknown.
func TrapName(oid string) string { return trapNames[norm(oid)] }
