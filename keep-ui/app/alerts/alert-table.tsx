import { Table, Callout } from "@tremor/react";
import { AlertsTableBody } from "./alerts-table-body";
import { AlertDto } from "./models";
import { CircleStackIcon } from "@heroicons/react/24/outline";
import {
  OnChangeFn,
  RowSelectionState,
  getCoreRowModel,
  useReactTable,
  getPaginationRowModel,
  PaginationState,
  ColumnDef,
  ColumnOrderState,
  VisibilityState,
} from "@tanstack/react-table";
import AlertPagination from "./alert-pagination";
import AlertColumnsSelect from "./alert-columns-select";
import AlertsTableHeaders from "./alert-table-headers";
import { useLocalStorage } from "utils/hooks/useLocalStorage";
import {
  getDataPageCount,
  getColumnsIds,
  getPaginatedData,
  getDefaultColumnVisibilityState,
} from "./alert-table-utils";

interface Props {
  alerts: AlertDto[];
  columns: ColumnDef<AlertDto>[];
  isAsyncLoading?: boolean;
  presetName: string;
  isMenuColDisplayed?: boolean;
  isRefreshAllowed?: boolean;
  rowSelection?: {
    state: RowSelectionState;
    onChange: OnChangeFn<RowSelectionState>;
  };
  rowPagination?: {
    state: PaginationState;
    onChange: OnChangeFn<PaginationState>;
  };
}

export function AlertTable({
  alerts,
  columns,
  isAsyncLoading = false,
  presetName,
  rowSelection,
  rowPagination,
  isRefreshAllowed = true,
}: Props) {
  const [columnOrder, setColumnOrder] = useLocalStorage<ColumnOrderState>(
    `column-order-${presetName}`,
    getColumnsIds(columns)
  );

  const [columnVisibility] = useLocalStorage<VisibilityState>(
    `column-visibility-${presetName}`,
    getDefaultColumnVisibilityState(columns)
  );

  const table = useReactTable({
    data: rowPagination
      ? getPaginatedData(alerts, rowPagination.state)
      : alerts,
    columns: columns,
    state: {
      columnVisibility: columnVisibility,
      columnOrder: columnOrder,
      rowSelection: rowSelection?.state,
      pagination: rowPagination?.state,
      columnPinning: {
        left: ["checkbox"],
        right: ["alertMenu"],
      },
    },
    initialState: {
      pagination: { pageSize: 10 },
    },
    getCoreRowModel: getCoreRowModel(),
    pageCount: rowPagination
      ? getDataPageCount(alerts.length, rowPagination.state)
      : undefined,
    getPaginationRowModel: rowPagination ? undefined : getPaginationRowModel(),
    enableRowSelection: rowSelection !== undefined,
    manualPagination: rowPagination !== undefined,
    onPaginationChange: rowPagination?.onChange,
    onColumnOrderChange: setColumnOrder,
    onRowSelectionChange: rowSelection?.onChange,
    enableColumnPinning: true,
  });

  return (
    <>
      {presetName && (
        <AlertColumnsSelect
          presetName={presetName}
          table={table}
          isLoading={isAsyncLoading}
        />
      )}
      {isAsyncLoading && (
        <Callout
          title="Getting your alerts..."
          icon={CircleStackIcon}
          color="gray"
          className="mt-5"
        >
          Alerts will show up in this table as they are added to Keep...
        </Callout>
      )}
      <Table>
        <AlertsTableHeaders
          columns={columns}
          table={table}
          presetName={presetName}
        />
        <AlertsTableBody table={table} showSkeleton={isAsyncLoading} />
      </Table>
      <AlertPagination table={table} isRefreshAllowed={isRefreshAllowed} />
    </>
  );
}
