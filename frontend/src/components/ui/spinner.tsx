// coss.com/ui (Cal.com Design System) - https://github.com/cosscom/ui
// Source: apps/ui/registry/default/ui (registry path; declared MIT in the repository)
// Copyright (c) coss.com. See THIRD_PARTY_NOTICES.md and coss-ui.LICENSE in this directory.
import { Loader2Icon } from "lucide-react";
import type React from "react";
import { cn } from "@/lib/utils";

export function Spinner({
  className,
  ...props
}: React.ComponentProps<typeof Loader2Icon>): React.ReactElement {
  return (
    <Loader2Icon
      aria-label="Loading"
      className={cn("animate-spin", className)}
      role="status"
      {...props}
    />
  );
}
