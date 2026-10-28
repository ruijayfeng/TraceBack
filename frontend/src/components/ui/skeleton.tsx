import { cn } from "@/lib/utils";

export function Skeleton({ className }: { className?: string }) {
  return <span aria-hidden className={cn("skeleton block animate-pulse rounded-sm bg-border/70", className)} />;
}

export function TextSkeleton({ lines = 3, className }: { lines?: number; className?: string }) {
  return (
    <div aria-hidden className={cn("flex flex-col gap-2", className)}>
      {Array.from({ length: lines }).map((_, index) => (
        <Skeleton className={index === lines - 1 ? "h-3 w-2/3" : "h-3 w-full"} key={index} />
      ))}
    </div>
  );
}

export function TableSkeleton({ rows = 6, columns = 6 }: { rows?: number; columns?: number }) {
  return (
    <div aria-busy="true" aria-label="正在加载列表" className="table-frame" role="status">
      <table className="list-table">
        <tbody>
          {Array.from({ length: rows }).map((_, row) => (
            <tr key={row}>
              {Array.from({ length: columns }).map((__, column) => (
                <td key={column}>
                  <Skeleton className={column === 0 ? "h-4 w-40" : column === columns - 1 ? "h-7 w-20" : "h-4 w-full"} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
