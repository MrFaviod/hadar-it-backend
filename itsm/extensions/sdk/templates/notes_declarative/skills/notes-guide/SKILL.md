# Notas del módulo

Este módulo es declarativo: no ejecuta código propio. El host ejecuta
`list_notes`, `get_note`, `put_note` y `delete_note` sobre el archivo SQLite
privado del módulo y valida cada nota contra el esquema declarado.

## Reglas

- Usa solo las operaciones declaradas en el manifiesto.
- `put_note` valida el esquema: `title` es obligatorio y `status` es `open` o `closed`.
- `expected_version` protege la actualización concurrente de una nota.
