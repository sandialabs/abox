package logging

// Action constants for audit logging.
const (
	// CLI invocation (logged for every command)
	ActionCLIInvoke = "cli.invoke"

	// Instance lifecycle
	ActionInstanceCreate  = "instance.create"
	ActionInstanceStart   = "instance.start"
	ActionInstanceStop    = "instance.stop"
	ActionInstanceRestart = "instance.restart"
	ActionInstanceRemove  = "instance.remove"

	// Declarative workflow
	ActionUp   = "workflow.up"
	ActionDown = "workflow.down"

	// Security mode
	ActionModeActive  = "security.mode.active"
	ActionModePassive = "security.mode.passive"

	// Allowlist
	ActionAllowlistAdd    = "allowlist.add"
	ActionAllowlistRemove = "allowlist.remove"
	ActionAllowlistEdit   = "allowlist.edit"
	ActionAllowlistReload = "allowlist.reload"

	// Filter blocks
	ActionHTTPBlock         = "http.block"
	ActionHTTPBlockSSRF     = "http.block.ssrf"
	ActionHTTPBlockFronting = "http.block.domain_fronting"

	// User commands
	ActionSSH     = "access.ssh"
	ActionSCP     = "access.scp"
	ActionTap     = "access.tap"
	ActionMount   = "access.mount"
	ActionUnmount = "access.unmount"

	// Snapshots
	ActionSnapshotCreate = "snapshot.create"
	ActionSnapshotRevert = "snapshot.revert"
	ActionSnapshotRemove = "snapshot.remove"

	// Instance data
	ActionProvision = "instance.provision"
	ActionExport    = "instance.export"
	ActionImport    = "instance.import"

	// Config
	ActionConfigEdit = "config.edit"

	// Port forwarding
	ActionForwardAdd     = "forward.add"
	ActionForwardRemove  = "forward.remove"
	ActionForwardRestart = "forward.restart"

	// Profile
	ActionProfileClear = "profile.clear"

	// Base images
	ActionBasePull   = "base.pull"
	ActionBaseImport = "base.import"
	ActionBaseRemove = "base.remove"

	// Cleanup
	ActionPrune      = "instance.prune"
	ActionImagePrune = "image.prune"

	// Infrastructure (no instance context)
	ActionSecurityFiltered = "security.filtered"
	ActionIptablesAddDNS   = "iptables.add_dns_redirect"
	ActionIptablesFlushDNS = "iptables.flush_dns_redirect"
	ActionTetragonDownload = "tetragon.download"
	ActionMonitorStatus    = "monitor.status"
	ActionMonitorShutdown  = "monitor.shutdown"
)

// AuditInstance logs an audit event to syslog for the specified instance.
// Events can be viewed with: journalctl -t abox
func AuditInstance(instance, action string, keysAndValues ...any) {
	args := append([]any{"action", action, "instance", instance}, keysAndValues...)
	Audit(action, args...)
}
