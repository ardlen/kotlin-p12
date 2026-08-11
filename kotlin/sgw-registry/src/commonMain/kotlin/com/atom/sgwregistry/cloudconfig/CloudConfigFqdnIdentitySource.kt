package com.atom.sgwregistry.cloudconfig

/**
 * Откуда брать identity-сегмент FQDN (`hashB(VIN)-{id}.{suffix}`).
 *
 * Явный [CloudConfigFromContext.buildAndSign] `fqdnIdentityId` всегда перекрывает этот выбор.
 */
enum class CloudConfigFqdnIdentitySource {
    /** `owner_id` / UID Ownership leaf (CES; совместимо с [CloudConfigCms.requireOwnerIdBinding]). */
    OwnerId,

    /** Invitation `tenant_id`. При tenant ≠ owner_id и `requireOwnerBinding=true` проверка FQDN упадёт. */
    TenantId,

    /** Сначала непустой `owner_id`, иначе `tenant_id`. */
    OwnerIdThenTenantId,

    /** Сначала непустой `tenant_id`, иначе `owner_id`. */
    TenantIdThenOwnerId,
}
