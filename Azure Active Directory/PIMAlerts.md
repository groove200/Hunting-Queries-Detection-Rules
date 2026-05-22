# PIM Security Alerts

## Query Information

#### Description
Detects Microsoft Entra Privileged Identity Management (PIM) security alerts and assigns severity based on the official Microsoft documentation.

Alert names from documentation:
- Administrators aren't using their privileged roles
- Roles don't require multifactor authentication for activation
- The organization doesn't have Microsoft Entra ID P2 or Microsoft Entra ID Governance
- Potential stale accounts in a privileged role
- Roles are being assigned outside of Privileged Identity Management
- There are too many Global Administrators
- Roles are being activated too frequently

#### Risk
These alerts indicate privilege governance gaps, potential policy violations, or active misuse of privileged access that can increase the likelihood and impact of identity compromise.

#### References
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
- https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts

## Sentinel
```KQL
AuditLogs
| where OperationName =~ "Triggered PIM alert"
| where Category =~ "RoleManagement"
| extend AlertDescription = TargetResources[0].displayName
| extend Severity = case(
	AlertDescription =~ "Roles are being assigned outside of Privileged Identity Management" or AlertDescription =~ "Role assigned outside of PIM", "High",
	AlertDescription =~ "Potential stale accounts in a privileged role", "Medium",
	AlertDescription =~ "Administrators aren't using their privileged roles", "Low",
	AlertDescription =~ "Roles don't require multifactor authentication for activation", "Low",
	AlertDescription =~ "The organization doesn't have Microsoft Entra ID P2 or Microsoft Entra ID Governance", "Low",
	AlertDescription =~ "There are too many Global Administrators", "Low",
	AlertDescription =~ "Roles are being activated too frequently", "Low",
	"Unknown"
)
| project-reorder TimeGenerated, OperationName, Category, AlertDescription, Severity
```
