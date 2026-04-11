import classNames from "classnames";

export interface RadioGroupProps {
  options: string[];
  value: string;
  className: string;
  onChange: (option: string) => void;
}

export function RadioGroup(props: RadioGroupProps) {
  return (
    <div className={props.className}>
      {props.options.map((option) => (
        <div
          key={option}
          onClick={() => props.onChange(option)}
          className={classNames("py-1 px-2 rounded-md cursor-pointer text-neutral-800 dark:text-neutral-300 transition-colors", {
            "bg-primary-100 text-primary-900 dark:bg-primary-900/50 dark:text-primary-100 shadow-sm": option === props.value,
          })}
        >
          {option}
        </div>
      ))}
    </div>
  );
}
