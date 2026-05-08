import { RotateCcw } from 'lucide-react';

interface RuleEditorProps {
  value: string;
  onChange: (value: string) => void;
  onReset: () => void;
}

export function RuleEditor({ value, onChange, onReset }: RuleEditorProps) {
  return (
    <div className="panel p-4">
      <div className="flex items-center justify-between gap-3">
        <h2 className="section-title">IDS Rules</h2>
        <button className="icon-button" type="button" onClick={onReset} title="Reset rules">
          <RotateCcw size={17} aria-hidden="true" />
          <span className="sr-only">Reset rules</span>
        </button>
      </div>
      <textarea
        className="mt-3 min-h-64 w-full resize-y rounded-lg border border-slate-300 bg-slate-950 p-3 font-mono text-sm leading-6 text-slate-100 outline-none ring-reef/30 transition focus:ring-4"
        value={value}
        spellCheck={false}
        onChange={(event) => onChange(event.currentTarget.value)}
        aria-label="Suricata-style IDS rules"
      />
    </div>
  );
}
