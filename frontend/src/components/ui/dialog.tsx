// coss.com/ui (Cal.com Design System) - https://github.com/cosscom/ui
// Source: apps/ui/registry/default/ui/dialog.tsx (registry path; declared MIT in the repository)
// Copyright (c) coss.com. See THIRD_PARTY_NOTICES.md and coss-ui.LICENSE in this directory.
// TraceBack adaptation: @base-ui/react 1.9.0 has no Dialog.Viewport; centering is applied to the
// Popup. Focus trap, Esc, scroll lock and focus restore remain Base UI Dialog behavior.
import { Dialog as DialogPrimitive } from "@base-ui/react/dialog";
import { XIcon } from "lucide-react";
import type React from "react";
import { cn } from "@/lib/utils";

export const Dialog: typeof DialogPrimitive.Root = DialogPrimitive.Root;
export const DialogTrigger: typeof DialogPrimitive.Trigger = DialogPrimitive.Trigger;
export const DialogClose: typeof DialogPrimitive.Close = DialogPrimitive.Close;

export function DialogBackdrop({ className, ...props }: DialogPrimitive.Backdrop.Props): React.ReactElement {
  return (
    <DialogPrimitive.Backdrop
      className={cn(
        "fixed inset-0 z-50 bg-black/32 transition-all duration-200 data-ending-style:opacity-0 data-starting-style:opacity-0 supports-[-webkit-touch-callout:none]:absolute",
        className,
      )}
      data-slot="dialog-backdrop"
      {...props}
    />
  );
}

export function DialogPopup({
  className,
  children,
  showCloseButton = true,
  closeProps,
  ...props
}: DialogPrimitive.Popup.Props & {
  showCloseButton?: boolean;
  closeProps?: DialogPrimitive.Close.Props;
}): React.ReactElement {
  return (
    <DialogPrimitive.Portal>
      <DialogBackdrop />
      <DialogPrimitive.Popup
        className={cn(
          "fixed left-1/2 top-1/2 z-50 flex w-[calc(100%-2rem)] max-w-lg -translate-x-1/2 -translate-y-1/2 flex-col rounded-2xl border border-border bg-popover p-6 text-popover-foreground shadow-lg/5 outline-none transition-[opacity,scale] duration-200",
          "data-ending-style:opacity-0 data-starting-style:opacity-0 data-ending-style:scale-98 data-starting-style:scale-98",
          className,
        )}
        data-slot="dialog-popup"
        {...props}
      >
        {children}
        {showCloseButton && (
          <DialogPrimitive.Close
            aria-label="关闭"
            className="absolute end-4 top-4 inline-flex size-8 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-accent-foreground focus-visible:ring-2 focus-visible:ring-ring"
            {...closeProps}
          >
            <XIcon aria-hidden size={18} />
          </DialogPrimitive.Close>
        )}
      </DialogPrimitive.Popup>
    </DialogPrimitive.Portal>
  );
}

export function DialogHeader({ className, ...props }: React.ComponentProps<"div">): React.ReactElement {
  return <div className={cn("flex flex-col gap-2 pb-4", className)} data-slot="dialog-header" {...props} />;
}

export function DialogFooter({ className, ...props }: React.ComponentProps<"div">): React.ReactElement {
  return <div className={cn("mt-4 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end", className)} data-slot="dialog-footer" {...props} />;
}

export function DialogTitle({ className, ...props }: DialogPrimitive.Title.Props): React.ReactElement {
  return <DialogPrimitive.Title className={cn("font-heading text-xl leading-none font-bold", className)} data-slot="dialog-title" {...props} />;
}

export function DialogDescription({ className, ...props }: DialogPrimitive.Description.Props): React.ReactElement {
  return <DialogPrimitive.Description className={cn("text-sm text-muted-foreground", className)} data-slot="dialog-description" {...props} />;
}

export { DialogPrimitive };
