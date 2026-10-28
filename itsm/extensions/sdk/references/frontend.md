# Native frontend reference

Trusted `frontend.js` runs in the authenticated same-origin host. Register Vue
component definitions; do not create an app, iframe, router or second design
system. The host supplies its full Vue runtime including template compilation.

```js
window.ITSMExtensions.register("record-registry", {
  components: { RecordList, RecordSummary }
});
```

Manifest page/panel component names resolve from this object. The registration
ID must equal the manifest ID. Use the generator for working definitions; the
fixed validator executes registration and checks every declared name.

## Host components: exact props

| Component | Public props/events |
| --- | --- |
| `ItsmTable` | `columns: [{field: 'title', label: 'Título'}]`, `rows`, `caption`, `empty`, `loading`, `rowKey` (template `row-key`). |
| `ItsmField` | `v-model` (`modelValue` / `update:modelValue`), required `label`, `id`, `type`, `hint`, `error`, `placeholder`, `autocomplete`, `required`, `disabled`, `multiline`, `rows`; emits `blur`. |
| `ItsmStatus` | `label`, `tone`: `ok`, `hold`, `warn` or `down`. |
| `ItsmError` | `error` string, `title`, `retry`, `retryLabel`; emits `retry`. |
| `ModalShell`, `AppIcon` | Native host dialog and icon components; retain host interaction and accessibility conventions. |

Use `field`, not `key`, for table columns; `label`, not `value`, for status;
`error`, not `message`, for errors. These are not compatibility aliases.

```html
<ItsmError v-if="error" :error="error" :retry="true" @retry="load" />
<ItsmTable v-else :columns="columns" :rows="records" :loading="loading"
           caption="Registros del módulo" row-key="id" />
```

## SDK capabilities

Components receive `sdk` as a prop:

- `await sdk.request("list_records", {limit: 20})` returns the operation JSON.
  It uses canonical same-origin POST, session and CSRF. It is not a general
  HTTP client: no URL, actor, SQL or arbitrary host operation input.
- `sdk.can(permission)` is a UI affordance for declared operation/contribution
  permissions and the live server grant, never authorization proof. The server
  rechecks every invocation.
- `sdk.navigate('#/core/hash')` uses host navigation;
  `sdk.navigate({page: 'records'})` opens an own manifest page. It cannot open
  another extension's private page.

An optional `asset` prop is a deeply frozen canonical asset copy. Never mutate
it. Native asset panels do not themselves add an asset-write API.

Preserve Spanish-tú copy, light/dark classes, responsive layout, keyboard and
screen-reader semantics. Use escaped text, not `v-html` with stored data.
Ignore stale async completions after reload/unmount; logout aborts host SDK
requests. Disable/uninstall removes pages and panels immediately without
breaking core routes. No bundled Vue, external component library or global
style reset is needed.
