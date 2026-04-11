import classNames from "classnames";

const computeHueFromString = (str: string) => {
  const hash = Array.from(str).reduce(
    (h, char) => 0 | (31 * h + char.charCodeAt(0)),
    0
  );
  // Abs value of hash modulo 120 gives a wider offset, starting strictly at 140
  // Resulting range: 140 (emerald green) to 260 (indigo/purple-blue)
  return 140 + (Math.abs(hash) % 120);
};

// Map important tags to explicit hues
const tagHueMap: Record<string, number> = {
  fishy: 210, // Blue
  blocked: 270, // Purple
  flag_out: 0, // Red
  flag_in: 120, // Green
};

export function tagToHue(tag: string) {
  return tagHueMap[tag] ?? computeHueFromString(tag);
}

export function tagToColor(tag: string) {
  return `hsl(${tagToHue(tag)}, 80%, 50%)`;
}

interface TagProps {
  tag: string;
  color?: string; // We can ignore explicitly passed full color strings to enforce theme, or we could handle it. We will ignore it for now as the CSS system is better.
  disabled?: boolean;
  excluded?: boolean;
  onClick?: () => void;
}

export const Tag = ({ tag, disabled = false, excluded = false, onClick }: TagProps) => {
  const hue = tagToHue(tag);

  let tagClass = "tag-base tag-dynamic";
  if (disabled) tagClass = "tag-base tag-disabled";
  if (excluded) tagClass = "tag-base tag-excluded";

  return (
    <div
      onClick={onClick}
      className={tagClass}
      style={(!disabled && !excluded) ? { '--tag-hue': hue } as any : undefined}
    >
      <span>{tag}</span>
    </div>
  );
};
