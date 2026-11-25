// Apps that keep the tenant in a session setting instead of a JWT:
//   create policy ... using (tenant_id = current_setting('app.tenant_id')::uuid)
/** @type {import("pg-tenant-probe").ProbeConfig} */
export default {
  schemas: ["app"],
  tenantColumn: "tenant_id",
  principals: [
    { name: "tenant A", role: "app_user", tenant: "a0f3c9e2-5b1d-4e8a-9c47-2d6b8e1f0a01", settings: { "app.tenant_id": "a0f3c9e2-5b1d-4e8a-9c47-2d6b8e1f0a01" } },
    { name: "tenant B", role: "app_user", tenant: "b7e4d1a8-3c2f-4b9e-8d56-7a1c9f2e0b02", settings: { "app.tenant_id": "b7e4d1a8-3c2f-4b9e-8d56-7a1c9f2e0b02" } },
  ],
};
