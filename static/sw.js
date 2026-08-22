self.addEventListener("push", (e) => {
  let data = { title: "Private.chat", body: "New message" };
  try { data = e.data.json(); } catch (err) {}

  e.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      tag: data.room || "private-chat",
      renotify: true
    })
  );
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil(
    clients.matchAll({ type: "window" }).then((clientList) => {
      for (const client of clientList) {
        if ("focus" in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow("/room");
    })
  );
});
