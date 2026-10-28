/*
 * Native components on the host Vue instance. No app, iframe, router,
 * bundled Vue or second design system. Approved same-origin code is trusted.
 */
(function () {
  "use strict";

  const host = window.ITSMExtensions;
  if (!host || typeof host.register !== "function") {
    throw new Error("ITSMExtensions.register is unavailable");
  }

  const RecordSummary = {
    name: "RecordSummary",
    props: {
      sdk: { type: Object, required: true },
      asset: { type: Object, default: null }
    },
    data() {
      return { record: null, error: "", loading: false, loadRevision: 0 };
    },
    watch: {
      asset: { handler: "load", immediate: true }
    },
    beforeUnmount() { this.loadRevision += 1; },
    methods: {
      async load() {
        const revision = ++this.loadRevision;
        const assetId = this.asset?.id;
        this.record = null;
        this.error = "";
        this.loading = false;
        if (!assetId) return;
        this.loading = true;
        try {
          const payload = await this.sdk.request("list_records", { asset_id: assetId, limit: 1 });
          if (revision !== this.loadRevision) return;
          this.record = payload.items[0] ?? null;
        } catch (problem) {
          if (revision !== this.loadRevision) return;
          this.error = problem?.message ?? "No se pudo cargar el registro del activo.";
        } finally {
          if (revision === this.loadRevision) this.loading = false;
        }
      }
    },
    computed: {
      statusText() {
        if (!this.record) return "Sin registro";
        return this.record.status === "closed" ? "Cerrado" : "Abierto";
      },
      statusTone() {
        return !this.record ? "hold" : this.record.status === "closed" ? "down" : "ok";
      }
    },
    template:
      '<div class="field extension-record-summary">' +
      '<span class="label">Registro del activo</span>' +
      '<ItsmError v-if="error" :error="error" :retry="true" @retry="load" />' +
      '<span v-else-if="loading" role="status">Cargando registro…</span>' +
      '<template v-else><ItsmStatus :label="statusText" :tone="statusTone" />' +
      '<span v-if="record" class="status">{{ record.title }}</span></template>' +
      '</div>'
  };

  const RecordList = {
    name: "RecordList",
    props: {
      sdk: { type: Object, required: true },
      asset: { type: Object, default: null }
    },
    data() {
      return {
        records: [], total: 0, error: "", loading: false, loadRevision: 0,
        columns: [
          { field: "title", label: "Título" },
          { field: "status", label: "Estado" }
        ]
      };
    },
    mounted() { this.load(); },
    beforeUnmount() { this.loadRevision += 1; },
    methods: {
      async load() {
        const revision = ++this.loadRevision;
        this.loading = true;
        this.error = "";
        try {
          const payload = await this.sdk.request("list_records", { limit: 20 });
          if (revision !== this.loadRevision) return;
          this.records = payload.items;
          this.total = payload.total;
        } catch (problem) {
          if (revision !== this.loadRevision) return;
          this.error = problem?.message ?? "No se pudieron cargar los registros.";
        } finally {
          if (revision === this.loadRevision) this.loading = false;
        }
      }
    },
    template:
      '<section class="extension-records">' +
      '<div class="toolbar"><h2>Registros</h2>' +
      '<span class="status">{{ total }} registros</span></div>' +
      '<ItsmError v-if="error" :error="error" :retry="true" @retry="load" />' +
      '<ItsmTable v-else :columns="columns" :rows="records" :loading="loading" ' +
      'caption="Registros del módulo" empty="Todavía no hay registros." row-key="id" />' +
      '</section>'
  };

  host.register("{{EXT_ID}}", { components: { RecordList, RecordSummary } });
})();
