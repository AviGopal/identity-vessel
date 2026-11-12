// What the database answers a CREATE with: the record it made (its id and the fields set). Issue checks that answer
// before handing a key out, so a stub that answers a CREATE with nothing models a write that made no row.
export const createdRow = (sql: string, params?: Record<string, any>): any[] =>
  /CREATE\s+api_key\b/i.test(sql) ? [{ id: 'api_key:created', ...(params ?? {}) }] : [];
