import { type ClassValue } from "clsx";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number): string {
  const normalizedBytes = Number.isFinite(bytes) && bytes > 0 ? bytes : 0;
  if (normalizedBytes === 0) {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB", "TB"] as const;
  const index = Math.min(Math.floor(Math.log(normalizedBytes) / Math.log(1024)), units.length - 1);
  const value = normalizedBytes / (1024 ** index);
  const precision = index === 0 || value >= 10 ? 0 : 1;

  return `${value.toFixed(precision)} ${units[index]}`;
}
