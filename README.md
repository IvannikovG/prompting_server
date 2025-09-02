cp .env.example .env
docker compose up --build

curl -s http://127.0.0.1:8000/health
# {"ok": true}



Сброс стейта NB после того как pairing с браузером произошел

// посмотреть что лежит
chrome.storage.local.get(null, x => console.log(x));

// удалить только связку
chrome.storage.local.remove(['agent_id','agent_token'], () => {
  console.log('agent creds removed');
});

// (опционально) полный wipe локального стора расширения
// chrome.storage.local.clear(() => console.log('storage cleared'));

// перезагрузить панель
window.location.reload();
// или жёстко перезапустить всё расширение:
// chrome.runtime.reload();
