import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function popupWindow(url: string, windowName: string, win:any, w:number, h:number) {
  const y = win.top.outerHeight / 2 + win.top.screenY - ( h / 2);
  const x = win.top.outerWidth / 2 + win.top.screenX - ( w / 2);
  return win.open(url, windowName, `toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=no, resizable=no, copyhistory=no, width=${w}, height=${h}, top=${y}, left=${x}`);
}
