import { createRoot } from "react-dom/client";
import App from "./App";
import "./tokens.css";
import "./workbench.css";
import "./views.css";

createRoot(document.getElementById("root")!).render(<App />);
