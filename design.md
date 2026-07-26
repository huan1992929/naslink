# Design — NASLink Identity Bridge

A locked design system for the NASLink administration app. Every management page reads this file before visual changes are made. Extend this system when the product grows; do not invent a new theme per page.

## Genre

Modern-minimal, written in a technical and utilitarian voice for enterprise IT administrators.

## Macrostructure family

- Marketing pages: not currently in scope.
- App pages: Workbench. Desktop uses one compact product navigation bar. Each page places its functional title, local tabs and primary actions in one page toolbar, with operational content immediately below.
- Content pages: Long Document, only for future manuals and deployment guides.

## Theme

Custom light technical palette anchored on the existing NASLink phosphor-lime signal.

- `--color-paper` oklch(98.2% 0.007 145)
- `--color-paper-2` oklch(96% 0.009 145)
- `--color-paper-3` oklch(93% 0.012 145)
- `--color-ink` oklch(18% 0.018 145)
- `--color-ink-2` oklch(29% 0.018 145)
- `--color-rule` oklch(88% 0.012 145)
- `--color-accent` oklch(80% 0.18 126)
- `--color-focus` oklch(58% 0.20 130)

Accent is a signal, not a surface. It appears on the active navigation marker, focus rings, short status badges and primary actions only.

## Typography

- Display: Avenir Next, weight 700, roman.
- Body: PingFang SC, weight 400; Microsoft YaHei and Avenir Next are local fallbacks.
- Mono: SFMono-Regular for IDs, endpoints, versions and tabular technical values.
- Display tracking: -0.025em.
- App page title: `--text-display` = clamp(1.875rem, 2.4vw, 2.5rem).

The app must remain fully usable without loading external font files.

## Spacing

4-point named scale. Values live in `tokens.css`. UI styles use named tokens and no improvised spacing scale.

## Motion

- Easings: `--ease-out`, `--ease-in`, `--ease-in-out` from `tokens.css`.
- Reveal pattern: content crossfade only when changing page or local tab.
- Buttons use a one-pixel press displacement.
- Reduced-motion fallback: opacity-only, no more than 150 ms.

## Microinteractions stance

- Silent success when the changed state is already visible.
- Error toasts remain fixed and name the failed operation.
- Focus is immediate; focus rings never animate.
- No decorative loops, hover-only actions or celebratory effects.

## CTA voice

- Primary: compact lime fill, dark ink, 44 px control height, specific verb.
- Secondary: paper fill, visible border, dark ink.
- Destructive: pale red surface plus red text; typed confirmation remains required for DSM writes.

## Per-page allowances

- App pages must not use hero illustration or decorative enrichment; the working data is the content.
- Configuration-heavy pages may split into local tabs to keep one task visible at a time.
- Tables may scroll inside their own container on tablet and collapse to labelled rows on phones.

## What pages MUST share

- NASLink wordmark and three-bar mark.
- Light cool paper, lime signal accent, and control geometry.
- Display, body and mono roles.
- Compact horizontal product navigation on desktop and a disclosure navigation on mobile.
- Small stacked page titles; no section eyebrows or large marketing headlines.

## What pages MAY differ on

- Local page tabs and task-specific action placement.
- Density of tables versus forms.
- Compact empty-state message and its corrective action.

## Exports

### tokens.css

The canonical file is [`tokens.css`](tokens.css).

### Tailwind v4 `@theme`

```css
@theme {
  --color-paper: oklch(98.2% 0.007 145);
  --color-paper-2: oklch(96% 0.009 145);
  --color-paper-3: oklch(93% 0.012 145);
  --color-rule: oklch(88% 0.012 145);
  --color-rule-2: oklch(78% 0.014 145);
  --color-muted: oklch(50% 0.014 145);
  --color-neutral: oklch(38% 0.016 145);
  --color-ink-2: oklch(29% 0.018 145);
  --color-ink: oklch(18% 0.018 145);
  --color-accent: oklch(80% 0.18 126);
  --color-focus: oklch(58% 0.20 130);
  --font-display: "Avenir Next", "PingFang SC", sans-serif;
  --font-body: "PingFang SC", "Microsoft YaHei", sans-serif;
  --font-outlier: "SFMono-Regular", Menlo, monospace;
  --spacing-xs: 0.75rem;
  --spacing-sm: 1rem;
  --spacing-md: 1.5rem;
  --spacing-lg: 2rem;
  --text-sm: 0.875rem;
  --text-base: 1rem;
  --text-xl: 1.5rem;
  --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
  --radius-card: 0.625rem;
  --radius-input: 0.5rem;
}
```

### DTCG `tokens.json`

```json
{
  "$schema": "https://design-tokens.github.io/community-group/format/",
  "color": {
    "paper": { "$value": "oklch(98.2% 0.007 145)", "$type": "color" },
    "paper-2": { "$value": "oklch(96% 0.009 145)", "$type": "color" },
    "ink": { "$value": "oklch(18% 0.018 145)", "$type": "color" },
    "rule": { "$value": "oklch(88% 0.012 145)", "$type": "color" },
    "accent": { "$value": "oklch(80% 0.18 126)", "$type": "color" },
    "focus": { "$value": "oklch(58% 0.20 130)", "$type": "color" }
  },
  "font": {
    "display": { "$value": "Avenir Next, PingFang SC, sans-serif", "$type": "fontFamily" },
    "body": { "$value": "PingFang SC, Microsoft YaHei, sans-serif", "$type": "fontFamily" },
    "outlier": { "$value": "SFMono-Regular, Menlo, monospace", "$type": "fontFamily" }
  },
  "space": {
    "xs": { "$value": "0.75rem", "$type": "dimension" },
    "sm": { "$value": "1rem", "$type": "dimension" },
    "md": { "$value": "1.5rem", "$type": "dimension" },
    "lg": { "$value": "2rem", "$type": "dimension" }
  }
}
```

### shadcn/ui CSS variables

```css
:root {
  --background: 98.2% 0.007 145;
  --foreground: 18% 0.018 145;
  --card: 96% 0.009 145;
  --card-foreground: 18% 0.018 145;
  --primary: 80% 0.18 126;
  --primary-foreground: 18% 0.018 145;
  --secondary: 93% 0.012 145;
  --secondary-foreground: 29% 0.018 145;
  --muted: 88% 0.012 145;
  --muted-foreground: 50% 0.014 145;
  --destructive: 55% 0.19 28;
  --border: 88% 0.012 145;
  --input: 78% 0.014 145;
  --ring: 58% 0.20 130;
  --radius: 0.625rem;
}
```
