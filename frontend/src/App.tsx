import { BrowserRouter, Routes, Route, Outlet } from "react-router-dom";
import { Suspense } from "react";
import { useHotkeys } from 'react-hotkeys-hook';

import "./App.css";
import { Header } from "./components/Header";
import { Home } from "./pages/Home";
import { FlowList } from "./components/FlowList";
import { FlowView } from "./pages/FlowView";
import { DiffView } from "./pages/DiffView";
import { ClustersView } from "./pages/ClustersView";
import { ShapesView } from "./pages/ShapesView";
import { TemplatesView } from "./pages/TemplatesView";
import { ChainsView } from "./pages/ChainsView";
import { ActuatorsView } from "./pages/ActuatorsView";
import { Corrie } from "./components/Corrie";
import { ThemeProvider } from "./hooks/useTheme";

function App() {
  useHotkeys('esc', () => (document.activeElement as HTMLElement).blur(), {enableOnFormTags: true});
  return (
    <ThemeProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Home />} />
            <Route
              path="flow/:id"
              element={
                <Suspense>
                  <FlowView />
                </Suspense>
              }
            />
            <Route
              path="diff"
              element={
                <Suspense>
                  <DiffView />
                </Suspense>
              }
            />
            <Route
              path="clusters"
              element={
                <Suspense>
                  <ClustersView />
                </Suspense>
              }
            />
            <Route
              path="shapes"
              element={
                <Suspense>
                  <ShapesView />
                </Suspense>
              }
            />
            <Route
              path="templates"
              element={
                <Suspense>
                  <TemplatesView />
                </Suspense>
              }
            />
            <Route
              path="chains"
              element={
                <Suspense>
                  <ChainsView />
                </Suspense>
              }
            />
            <Route
              path="actuators"
              element={
                <Suspense>
                  <ActuatorsView />
                </Suspense>
              }
            />
            <Route
              path="corrie/"
              element={
                <Suspense>
                  <Corrie />
                </Suspense>
              }
            />
          </Route>
          <Route path="*" element={<PageNotFound />} />
        </Routes>
      </BrowserRouter>
    </ThemeProvider>
  );
}

function Layout() {
  return (
    <div className="grid-container bg-app text-app min-h-screen">
      <header className="header-area border-b border-subtle bg-panel flex flex-col">
          <Header></Header>
      </header>
      <aside className="flow-list-area border-r border-subtle bg-sidebar">
        <Suspense>
          <FlowList></FlowList>
        </Suspense>
      </aside>
      <main className="flow-details-area bg-main">
        <Outlet />
      </main>
      <footer className="footer-area"></footer>
    </div>
  );
}


function PageNotFound() {
  return (
    <div>
      <h2>404 Page not found</h2>
    </div>
  );
}

export default App;
