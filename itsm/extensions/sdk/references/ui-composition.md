# Business UI composition (SDK v1)

The optional `frontend.contributions` array extends the existing frontend contract.
Keep `entry`, `pages` and `assetPanels`; old packages without `contributions` remain
valid. The generator emits an empty array. This is a manifest contract, not a DOM
patch API or an authorization grant. Trusted Vue components still register through
`ITSMExtensions.register`; raw HTML and CSS selectors are not targets.

## Declaration

Each item has a unique `id`, nonempty `label`, declared extension `permission`,
explicit `target`, and `mode` (`add`, `hide`, `replace`). `add` and `replace` require
a registered `component`; `hide` forbids it. Optional `icon` follows the existing
contribution format. Optional integer `order` defaults to 0, between -10000 and
10000. IDs are unique across pages, asset panels and these declarations.

```json
{
  "frontend": {
    "entry": "frontend.js",
    "pages": [],
    "assetPanels": [],
    "contributions": [
      {
        "id": "extra-report",
        "label": "Informe de registros",
        "target": "nav.reports",
        "mode": "add",
        "permission": "ext_record_registry.records_read",
        "component": "RecordList",
        "order": 10
      },
      {
        "id": "hide-history",
        "label": "Ocultar historial estándar",
        "target": "asset.panel.history",
        "mode": "hide",
        "permission": "ext_record_registry.records_read"
      },
      {
        "id": "inventory-summary",
        "label": "Resumen del inventario",
        "target": "page.inventory",
        "mode": "replace",
        "permission": "ext_record_registry.records_read",
        "component": "RecordList"
      }
    ]
  }
}
```

## Target catalogue

The shipped `schema/extension.schema.json` `$defs.uiTarget.enum` is the exhaustive,
consumed catalogue. Unknown targets fail validation. Names are identifiers, not
translated labels or `data-od-id` selectors.

| Prefix | Target suffixes |
| --- | --- |
| `nav.` | `panel`, `inventory`, `conversation`, `maintenance`, `monitoring`, `infrastructure`, `datos`, `reports`, `warranties`, `labels`, `people`, `help`, `extensions` |
| `page.` | `panel`, `inventory`, `conversation`, `maintenance`, `monitoring`, `map`, `graph`, `datos`, `reports`, `warranties`, `labels`, `people`, `person`, `detail`, `incident`, `reportAsset`, `monitorDevice`, `monitorAlert`, `notifications`, `help` |
| `widget.` | `availability`, `alerts`, `distribution`, `infrastructure`, `activity`, `maintenance`, `warranties`, `inventory`, `latency`, `incidents` |
| `asset.panel.` | `warranty`, `attachments`, `qr`, `relations`, `maintenance`, `monitoring`, `history` |
| `asset.action.` | `edit`, `assign`, `return`, `transfer`, `ask`, `duplicate`, `change-status`, `restore`, `archive`, `retire`, `purge`, `delete` |
| `config.` | `apariencia`, `general`, `categorias`, `activos`, `sedes`, `personas`, `integraciones`, `relaciones`, `mantenimiento`, `supervision`, `alertas`, `notificaciones`, `mapas`, `datos`, `reportes`, `garantias`, `qr`, `etiquetas` |

`nav.extensions` accepts only `add`: hiding/replacing the whole extension group
could remove contributions owned by someone else. Generic `nav.config` and
wildcards are deliberately absent, so protected administration remains reachable.
Login, users/user, permission administration (`seguridad`), extension management,
review/recovery (`extensiones`) and advanced system operations (`sistema`) are
core-owned and cannot be named as composition targets.

## Host behavior and lifecycle

For an authorized, enabled extension, `add` inserts a component at the named
business surface; it does not overwrite the original. Added pages use extension
hash routes, not an unbounded replacement router. `hide` removes the named core
surface; `replace` substitutes the registered Vue component. Existing page and
asset-panel contributions retain their original behavior.

Additions are ordered by `order`, extension ID, then contribution ID. Competing
hide/replace declarations use that same ascending order to select one winner.
An unauthorized, malformed or unavailable contribution is ignored at runtime and
the core remains usable. Backend manifest validation is strict and rejects these
packages before approval. Disabling/uninstalling removes only the affected
extension's declarations and restores the core or the next eligible contribution.

The component context remains the existing frozen `sdk` and read-only asset when
applicable. `sdk.can` only controls affordances. The server reauthorizes operations
on every call, independently of what is shown or hidden. Composition does not add
permissions, bypass CSRF, provide hostile-code isolation or authorize lifecycle
changes. Register every declared component: the fixed validator checks components
from all three arrays, excluding component-free `hide` declarations.

The backend contract can be validated and packaged independently of host rollout.
A host without composition support will still expose only legacy pages and panels;
manifest acceptance alone is not evidence that a particular UI target is rendered.
