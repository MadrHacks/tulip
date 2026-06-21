import { format, parse } from "date-fns";
import { Suspense, useState } from "react";
import { useHotkeys } from 'react-hotkeys-hook';
import {
  Link,
  useParams,
  useSearchParams,
  useNavigate,
} from "react-router-dom";
import ReactDiffViewer from "react-diff-viewer";
import { SunIcon, MoonIcon } from "@heroicons/react/solid";
import { useTheme } from "../hooks/useTheme";

import {
  END_FILTER_KEY,
  SERVICE_FILTER_KEY,
  START_FILTER_KEY,
  TEXT_FILTER_KEY,
  FIRST_DIFF_KEY,
  SECOND_DIFF_KEY,
  SERVICE_REFETCH_INTERVAL_MS,
  REPR_ID_KEY,
  SIMILARITY_FILTER_KEY,
} from "../const";
import {
  useGetFlowQuery,
  useGetServicesQuery,
} from "../api";
import { getTickStuff } from "../tick";

function ServiceSelection() {
  const FILTER_KEY = SERVICE_FILTER_KEY;

  // TODO add all, maybe user react-select

  const { data: services } = useGetServicesQuery(undefined, {
    pollingInterval: SERVICE_REFETCH_INTERVAL_MS,
  });

  const service_select = [
    {
      ip: "",
      port: 0,
      name: "all",
    },
    ...(services || []),
  ];
  let [searchParams, setSearchParams] = useSearchParams();
  return (
    <select
      className="input-default w-20"
      value={searchParams.get(FILTER_KEY) ?? ""}
      onChange={(event) => {
        let serviceFilter = event.target.value;
        if (serviceFilter && serviceFilter != "all") {
          searchParams.set(FILTER_KEY, serviceFilter);
        } else {
          searchParams.delete(FILTER_KEY);
        }
        setSearchParams(searchParams);
      }}
    >
      {service_select.map((service) => (
        <option key={service.name} value={service.name}>
          {service.name}
        </option>
      ))}
    </select>
  );
}

function TextSearch() {
  const FILTER_KEY = TEXT_FILTER_KEY;
  let [searchParams, setSearchParams] = useSearchParams();
  useHotkeys('s', (e) => {
    let el = document.getElementById('search') as HTMLInputElement;
    el?.focus();
    el?.select();
    e.preventDefault()
  });
  return (
    <input
      type="text"
      className="input-default"
      placeholder="regex"
      id="search"
      value={searchParams.get(FILTER_KEY) || ""}
      onChange={(event) => {
        let textFilter = event.target.value;
        if (textFilter) {
          searchParams.set(FILTER_KEY, textFilter);
        } else {
          searchParams.delete(FILTER_KEY);
        }
        setSearchParams(searchParams);
      }}
    ></input>
  );
}


function StartDateSelection() {
  let { startTickParam, setTimeParam } = getTickStuff();
  return (
    <input
      className="input-default w-20"
      id="startdateselection"
      type="number"
      placeholder="from"
      value={startTickParam}
      onChange={(event) => {
        setTimeParam(event.target.value == "" ? null : parseInt(event.target.value), START_FILTER_KEY);
      }}
    ></input>
  );
}

function EndDateSelection() {
  let { endTickParam, setTimeParam } = getTickStuff();
  return (
    <input
      className="input-default w-20"
      id="enddateselection"
      type="number"
      placeholder="to"
      value={endTickParam}
      onChange={(event) => {
        setTimeParam(event.target.value == "" ? null : parseInt(event.target.value), END_FILTER_KEY);
      }}
    ></input>
  );
}

function FirstDiff() {
  let params = useParams();
  let [searchParams, setSearchParams] = useSearchParams();
  const [firstFlow, setFirstFlow] = useState<string>(
    searchParams.get(FIRST_DIFF_KEY) ?? ""
  );

  function setFirstDiffFlow() {
    let textFilter = params.id;
    let reprId = searchParams.get(REPR_ID_KEY);
    let reprIdSlug = reprId ? `${textFilter}:${reprId}` : `${textFilter}`
    if (textFilter) {
      searchParams.set(FIRST_DIFF_KEY, reprIdSlug);
      setFirstFlow(reprIdSlug);
    } else {
      searchParams.delete(FIRST_DIFF_KEY);
      setFirstFlow("");
    }
    setSearchParams(searchParams);
  }

  useHotkeys("f", () => {
    setFirstDiffFlow();
  });

  return (
    <input
      type="text"
      className="input-default flex-1 min-w-0"
      placeholder="First Diff ID"
      readOnly
      value={firstFlow}
      onClick={(event) => setFirstDiffFlow()}
      onContextMenu={(event) => {
        searchParams.delete(FIRST_DIFF_KEY);
        setFirstFlow("");
        setSearchParams(searchParams);
        event.preventDefault();
      }}
    ></input>
  );
}

function SecondDiff() {
  let params = useParams();
  let [searchParams, setSearchParams] = useSearchParams();
  const [secondFlow, setSecondFlow] = useState<string>(
    searchParams.get(SECOND_DIFF_KEY) ?? ""
  );

  function setSecondDiffFlow() {
    let textFilter = params.id;
    let reprId = searchParams.get(REPR_ID_KEY);
    let reprIdSlug = reprId ? `${textFilter}:${reprId}` : `${textFilter}`
    if (textFilter) {
      searchParams.set(SECOND_DIFF_KEY, reprIdSlug);
      setSecondFlow(reprIdSlug);
    } else {
      searchParams.delete(SECOND_DIFF_KEY);
      setSecondFlow("");
    }
    setSearchParams(searchParams);
  }

  useHotkeys("g", () => {
    setSecondDiffFlow();
  });

  return (
    <input
      type="text"
      className="input-default flex-1 min-w-0"
      placeholder="Second Flow ID"
      readOnly
      value={secondFlow}
      onClick={(event) => setSecondDiffFlow()}
      onContextMenu={(event) => {
        searchParams.delete(SECOND_DIFF_KEY);
        setSecondFlow("");
        setSearchParams(searchParams);
        event.preventDefault();
      }}
    ></input>
  );
}

function Diff() {
  let params = useParams();

  let [searchParams] = useSearchParams();

  let navigate = useNavigate();

  function navigateToDiff() {
    navigate(`/diff?${searchParams}`, { replace: true });
  }

  useHotkeys("d", () => {
    navigateToDiff();
  });

  return (
    <button
      className="btn-primary"
      onClick={() => {
        navigateToDiff()
      }}
    >
      Diff
    </button>
  );
}

function SimilaritySlider() {
  let [searchParams, setSearchParams] = useSearchParams();
  // Initialize state to keep track of the value
  const [value, setValue] = useState(searchParams.get(SIMILARITY_FILTER_KEY) ?? 90); // You can set the initial value to whatever you prefer

  // Function to update the state based on input changes
  const handleChange = (event:any) => {
    setValue(event.target.value);
    searchParams.set(SIMILARITY_FILTER_KEY, event.target.value);
    setSearchParams(searchParams);
  };

  return (
    <div className="flex items-center">
      <div className="pr-3 flex flex-col text-sm justify-center">
        <span>
          Similarity:
        </span>
        <input
          className="accent-primary-600 dark:accent-primary-400"
          style={{paddingTop:0, paddingBottom:0}}
          type="range"
          min="0" // Set the minimum value of the range
          max="100" // Set the maximum value of the range
          value={value} // Bind the range input to the value in the state
          onChange={handleChange} // Update the state when the range value changes
        />
      </div>
      <input
        className="input-default w-16"
        type="number"
        min="0" // Set the minimum value for the number input
        max="100" // Set the maximum value for the number input
        value={value} // Bind the number input to the value in the state
        onChange={handleChange} // Update the state when the number value changes
      />
    </div>
  );
}

function ThemeToggle() {
  const { isDark, toggleDark } = useTheme();
  return (
    <button onClick={toggleDark} className="btn-secondary ml-2 flex items-center justify-center p-1" title="Toggle Dark Mode">
      {isDark ? <SunIcon className="w-5 h-5 text-yellow-500" /> : <MoonIcon className="w-5 h-5 text-gray-700" />}
    </button>
  );
}

export function Header() {
  let { currentTick, setToLastnTicks, setTimeParam } = getTickStuff();
  let [searchParams] = useSearchParams();
  const [showDiffPanel, setShowDiffPanel] = useState(false);

  useHotkeys('a', () => setToLastnTicks(5));
  useHotkeys('c', () => {
    (document.getElementById("startdateselection") as HTMLInputElement).value = "";
    (document.getElementById("enddateselection") as HTMLInputElement).value = "";
    setTimeParam(null, START_FILTER_KEY);
    setTimeParam(null, END_FILTER_KEY);
  });

  return (
    <>
      <div className="header w-full">
        <div className="flex items-center">
          <Link to={`/?${searchParams}`} className="flex items-center">
            <div className="header-icon">🌷</div>
          </Link>
        </div>
        <TextSearch />
        <Suspense>
          <ServiceSelection />
        </Suspense>
        <StartDateSelection />
        <EndDateSelection />
        <button
          className="btn-primary"
          onClick={() => setToLastnTicks(5)}
        >
          Last 5
        </button>
        <Link to={`/corrie?${searchParams}`} className="flex items-center">
          <button className="btn-primary">
            Graph
          </button>
        </Link>
        <Link to={`/clusters?${searchParams}`} className="flex items-center">
          <button className="btn-primary">
            Clusters
          </button>
        </Link>
        <Link to={`/templates?${searchParams}`} className="flex items-center">
          <button className="btn-primary">
            Templates
          </button>
        </Link>
        <Link to={`/chains?${searchParams}`} className="flex items-center">
          <button className="btn-primary">
            Chains
          </button>
        </Link>
        <button
          className="btn-primary"
          onClick={() => setShowDiffPanel((v) => !v)}
        >
          Diff Tool
        </button>
        <SimilaritySlider />
        <div className="ml-auto flex items-center gap-2">
          <ThemeToggle />
          <span className="text-mono text-sm px-2 py-1 bg-secondary text-secondary rounded-md">
            T: {currentTick}
          </span>
        </div>
      </div>
      {showDiffPanel && (
        <div className="w-full flex items-center gap-2 py-2 px-2 border-t border-subtle bg-panel">
          <span className="text-sm font-semibold text-secondary whitespace-nowrap">Diff Selection:</span>
          <FirstDiff />
          <SecondDiff />
          <div className="ml-auto flex items-center">
            <Suspense>
              <Diff />
            </Suspense>
          </div>
        </div>
      )}
    </>
  );
}
