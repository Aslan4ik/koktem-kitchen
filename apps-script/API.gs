/**
 * Дополнительный файл API.gs в существующем Apps Script проекте.
 * Существующие getDashboard, getJournal, saveReading и exportJournalPdf не менять.
 * Script property KOKTEM_API_SECRET устанавливается вручную.
 */
function doPost(e) {
  try {
    const payload = JSON.parse(e?.postData?.contents || '{}');
    const required = PropertiesService.getScriptProperties().getProperty('KOKTEM_API_SECRET');
    if (!required || typeof payload.secret !== 'string' ||
        !kcConstantTimeEquals_(required, payload.secret)) {
      return kcApiOutput_({ ok: false, error: 'Доступ запрещён' });
    }
    const methods = {
      getDashboard: { fn: getDashboard, count: 0 },
      getJournal: { fn: getJournal, count: 1 },
      saveReading: { fn: saveReading, count: 1 },
      exportJournalPdf: { fn: exportJournalPdf, count: 1 }
    };
    const method = methods[payload.action];
    const args = Array.isArray(payload.args) ? payload.args : [];
    if (!method || args.length !== method.count ||
        JSON.stringify(args).length > 20000) throw Error('Некорректный запрос');
    const result = method.fn.apply(null, args);
    return kcApiOutput_({ ok: true, result });
  } catch (error) {
    return kcApiOutput_({ ok: false, error: String(error.message || 'Ошибка сервера') });
  }
}
function kcApiOutput_(data) {
  return ContentService.createTextOutput(JSON.stringify(data))
    .setMimeType(ContentService.MimeType.JSON);
}
function kcConstantTimeEquals_(a, b) {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}
