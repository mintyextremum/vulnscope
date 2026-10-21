import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";

function render() {
  ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
}

// In a plain browser during development there is no backend: stand one in, so
// the interface runs its real code paths. `import.meta.env.DEV` is inlined as
// false in a production build, which drops this branch and the import with it.
if (import.meta.env.DEV && !("__TAURI_INTERNALS__" in window)) {
  void import("./devbackend").then(({ installDevBackend }) => {
    installDevBackend();
    render();
  });
} else {
  render();
}
