use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CmdLevel {
    Read,
    Write,
    Admin,
}

impl CmdLevel {
    /// Wire string the agent consumes. Read/Write/Admin only — "destructive"
    /// is a per-command literal owned by callers, not this enum.
    pub fn as_str(self) -> &'static str {
        match self {
            CmdLevel::Read => "read",
            CmdLevel::Write => "write",
            CmdLevel::Admin => "admin",
        }
    }
}

/// Pure fold: highest level implied by a set of permission keys. Shared by the
/// DB path and the unit test so the mapping is tested without a database.
fn fold_level(keys: &[&str]) -> Option<CmdLevel> {
    let mut level: Option<CmdLevel> = None;
    for k in keys {
        let l = match *k {
            "*:*" => CmdLevel::Admin,
            "vps:create" | "vps:edit" | "vps:delete" | "vps:*" => CmdLevel::Write,
            "vps:read" => CmdLevel::Read,
            _ => continue,
        };
        level = Some(level.map_or(l, |cur| cur.max(l)));
    }
    level
}

/// Highest command authority the user holds over the VPS/agent surface.
/// `Ok(None)` = no `vps:*`/`*:*` permission → caller must deny (403).
pub async fn user_vps_level(
    db: &sqlx::PgPool,
    user_id: Uuid,
) -> Result<Option<CmdLevel>, sqlx::Error> {
    let keys: Vec<String> = sqlx::query_scalar!(
        r#"SELECT p.key AS "key!" FROM user_roles ur
           JOIN role_permissions rp ON rp.role_id = ur.role_id
           JOIN permissions p ON p.id = rp.permission_id
           WHERE ur.user_id = $1
             AND p.key IN ('vps:read','vps:create','vps:edit','vps:delete','vps:*','*:*')"#,
        user_id
    )
    .fetch_all(db)
    .await?;
    let refs: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();
    Ok(fold_level(&refs))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn level_fold() {
        assert_eq!(fold_level(&[]), None);
        assert_eq!(fold_level(&["vps:read"]), Some(CmdLevel::Read));
        assert_eq!(
            fold_level(&["vps:read", "vps:create"]),
            Some(CmdLevel::Write)
        );
        assert_eq!(fold_level(&["vps:*"]), Some(CmdLevel::Write));
        assert_eq!(fold_level(&["*:*"]), Some(CmdLevel::Admin));
        assert_eq!(fold_level(&["vps:read", "*:*"]), Some(CmdLevel::Admin));
    }
}
