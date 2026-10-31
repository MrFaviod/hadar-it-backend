# Guía de licencias

- Las licencias viven en la base SQLite del módulo, nunca en la base del core.
- Las asignaciones guardan el `assetId` permanente; la existencia y el ciclo de
  vida se consultan con la capability `assets.read`.
- Si falta un contrato público, registra `extension_contract_gap` en vez de
  tocar estructuras privadas.
