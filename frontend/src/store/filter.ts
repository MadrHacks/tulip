import { createSlice, PayloadAction } from "@reduxjs/toolkit";

export interface TulipFilterState {
  filterFlags: string[];
  filterFlagids: string[];
  includeTags: string[];
  excludeTags: string[];
  tagIntersectionMode: "AND" | "OR";
  fuzzyHashes: string[];
  fuzzyHashIds: string[];
  includeFuzzyHashes: string[];
  excludeFuzzyHashes: string[];
  // startTick?: number;
  // endTick?: number;
  // service?: string;
  // textSearch?: string;
}

const initialState: TulipFilterState = {
  includeTags: [],
  excludeTags: [],
  filterFlags: [],
  filterFlagids: [],
  tagIntersectionMode: "OR",
  fuzzyHashes: [],
  fuzzyHashIds: [],
  includeFuzzyHashes: [],
  excludeFuzzyHashes: [],
};

export const filterSlice = createSlice({
  name: "filter",
  initialState,
  reducers: {
    // updateStartTick: (state, action: PayloadAction<number>) => {
    //   state.startTick = action.payload;
    // },
    // updateEndTick: (state, action: PayloadAction<number>) => {
    //   state.endTick = action.payload;
    // },
    toggleFilterTag: (state, action: PayloadAction<string>) => {
      var included = state.includeTags.includes(action.payload)
      var excluded = state.excludeTags.includes(action.payload)

      // If a user clicks a 'included' tag, the tag should be 'excluded' instead.
      if (included) {
        // Remove from included
        state.includeTags = state.includeTags.filter((t) => t !== action.payload);

        // Add to excluded
        state.excludeTags = [...state.excludeTags, action.payload]
      } else {
        // If the user clicks on an 'excluded' tag, the tag should be 'unset' from both include / exclude tags
        if (excluded) {
          // Remove from excluded
          state.excludeTags = state.excludeTags.filter((t) => t !== action.payload);
        } else {
          if (!included && !excluded) {
            // The tag was disabled, so it should be added to included now
            state.includeTags = [...state.includeTags, action.payload]
          }
        }
      }
    },
    toggleFilterFlags: (state, action: PayloadAction<string>) => {
      state.filterFlags = state.filterFlags.includes(action.payload)
          ? state.filterFlags.filter((t) => t !== action.payload)
          : [...state.filterFlags, action.payload];
    },
    toggleFilterFlagids: (state, action: PayloadAction<string>) => {
      state.filterFlagids = state.filterFlagids.includes(action.payload)
          ? state.filterFlagids.filter((t) => t !== action.payload)
          : [...state.filterFlagids, action.payload];
    },
    toggleTagIntersectMode: (state) => {
      state.tagIntersectionMode = state.tagIntersectionMode == "AND" ? "OR" : "AND";
    },
    toggleFilterFuzzyHashes: (state, action: PayloadAction<string[]>) => {
      var fuzzyHashes = action.payload[0];
      var id = action.payload[1];
      var included = state.includeFuzzyHashes.includes(fuzzyHashes);
      var excluded = state.excludeFuzzyHashes.includes(fuzzyHashes);

      // If the fuzzyHashes hash is new cache it
      if(!state.fuzzyHashes.includes(fuzzyHashes)) {
        state.fuzzyHashes = [...state.fuzzyHashes, fuzzyHashes];
        state.fuzzyHashIds = [...state.fuzzyHashIds, id];
      }

      if (included) {
        // If a user clicks a 'included' fuzzyHashes hash, the hash should be 'excluded' instead.
        state.includeFuzzyHashes = state.includeFuzzyHashes.filter((t) => t !== fuzzyHashes);
        state.excludeFuzzyHashes = [...state.excludeFuzzyHashes, fuzzyHashes];
      } else if (excluded) {
        // If the user clicks on an 'excluded' fuzzyHashes hash, the hash should be 'unset' from both include / exclude tags
        state.excludeFuzzyHashes = state.excludeFuzzyHashes.filter((t) => t !== fuzzyHashes);
      } else {
        // The tag was disabled, so it should be added to included now
        state.includeFuzzyHashes = [...state.includeFuzzyHashes, fuzzyHashes];
      }
    },
  },
});

export const { toggleFilterTag, toggleTagIntersectMode, toggleFilterFuzzyHashes } = filterSlice.actions;

export default filterSlice.reducer;
