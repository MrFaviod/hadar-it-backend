# Frontend reference (SDK v2, declarative views)

SDK v2 removes same-origin module JavaScript. Pages, asset panels, widgets and
asset actions are **declarative**: the manifest describes a view, and the host
renders it with its own Vue components and design system. A module bundle exists
only for an explicitly isolated iframe component.

## Declarative views

```json
"frontend": {
  "pages": [{
    "id": "records",
    "label": "Registros",
    "permission": "ext_record_registry.records_read",
    "view": {
      "table": {
        "operation": "list_records",
        "columns": [
          {"field": "title", "label": "Título"},
          {"field": "status", "label": "Estado"}
        ]
      }
    }
  }],
  "assetPanels": [{
    "id": "record-summary",
    "label": "Registros",
    "permission": "ext_record_registry.records_read",
    "view": {
      "table": {
        "operation": "list_records",
        "columns": [{"field": "title", "label": "Título"}],
        "filterAsset": "asset_id"
      }
    }
  }],
  "contributions": []
}
```

Three view shapes are allowed:

| Shape | Fields |
| --- | --- |
| `table` | `operation` (a declared operation), `columns` (`field`, `label`, optional `format`: `text`, `date`, `date-time`, `number`, `boolean`), optional `filterAsset` (a field name), optional `form` |
| `form` | `operation`, `fields` (`field`, `label`, `input`: `text`, `textarea`, `number`, `date`, `select`, `checkbox`, optional `required`, `options`), optional `assetField` (a field name) |
| `isolated` | `component` and optional `height` (120–2000) |

Every view declares `id`, `label`, a declared `permission` and optionally
`icon`. `filterAsset` is a field name, never a boolean: it says where the host
puts the selected asset's permanent id, and the manifest is rejected unless that
field exists on the operation the view names. For a handler operation it is a
declared top-level parameter (`"asset_id"`); for a declarative `list` it is a
declared collection property and the host sends it inside `filters`
(`{"assetId": "<id>"}`). `assetField` follows the same rule for a form: a
declared handler parameter, or a collection property written into `data` by a
declarative `put`. The module decides what to store. The host renders
labels, inputs, tables, empty states, errors and loading with its own components,
so the module cannot inject markup, CSS or a second design system.

`actions` add an entry to the asset action menu:

```json
"actions": [{
  "id": "flag-record", "label": "Marcar registro",
  "target": "asset.action",
  "permission": "ext_record_registry.records_write",
  "operation": "create_record",
  "confirm": "¿Crear el registro para este activo?"
}]
```

`contributions` keep the `add`/`hide` slot model: `hide` requires no
component, `add`/`replace` require an isolated component and therefore
`frontend.entry`.

## Isolated components

Only a `view.isolated` component (or a non-`hide` contribution) may ship a
bundle, declared as `frontend.entry: "frontend.js"`. It is loaded into an iframe
with `sandbox="allow-scripts"`: an opaque origin with no cookies, no host DOM
and no storage access. The host inlines its own Vue runtime and component kit
into the frame.

```js
window.ITSMExtension.register({
  components: { RecordBoard }
});
```

Registered components must provide a render function, authored or already precompiled
for the shipped Vue 3.5.13 runtime. For example:

```js
const RecordBoard = { render() { return Vue.h('p', 'Records'); } };
window.ITSMExtension.register({ components: { RecordBoard } });
```

Raw `template` options are unsupported, even alongside `render`. Before mounting,
the frame checks all registered siblings and local components, including `mixins`
and `extends`; unsupported definitions produce a visible localized alert, not an
empty mount. Option-only mixins/extends need no render; registered/local components
do. Functional components are supported. This replaces the previously documented
raw-template example, which CSP already blocked at runtime. Migrate all template
options to render functions and omit `template` from delivered bundles. The host
adds no compiler/build pipeline, never evaluates modules in its privileged context,
and does not relax enforcing frame CSP. `itsm:ready` means bridge readiness, not
successful mount. Declarative views and the rest of the extension remain available.

The frame talks to the host only through `postMessage`:

| Direction | Messages |
| --- | --- |
| Module → host | `itsm:request` (own declared operation), `itsm:navigate` (own page), `itsm:resize`, `itsm:ready` |
| Host → module | `itsm:init` (asset, theme, principal projection), `itsm:response`, `itsm:theme` |

A request may name only the current extension's declared operations; the host
re-checks authority on every call. `itsm:navigate` cannot open another module's
private page. `itsm:resize` is bounded by the host. No message grants
permissions, and nothing is read from the parent window.

## Permissions and lifecycle

`sdk.can(permission)` does not exist for declarative views: the host shows or
hides a view using the same live authorization it uses for invocation, and the
server rechecks every call. Disable and uninstall remove the module's pages,
panels, widgets and actions immediately.

## Validator evidence

For declarative views the validator checks that every `view.table`/`view.form`
names a declared operation and reports the count of host-rendered views. For an
isolated bundle it parses the JavaScript, executes it in the sandboxed JS
harness and requires `window.ITSMExtension.register({components})` plus every
declared component name.
