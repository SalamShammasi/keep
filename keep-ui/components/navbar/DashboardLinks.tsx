'use client';
import { DndContext, useSensor, useSensors, PointerSensor, TouchSensor, rectIntersection } from "@dnd-kit/core";
import { SortableContext, arrayMove } from "@dnd-kit/sortable";
import { usePathname, useRouter } from "next/navigation";
import { DashboardLink } from "./DashboardLink";
import { Subtitle, Button, Badge } from "@tremor/react";
import { Disclosure } from "@headlessui/react";
import { IoChevronUp } from "react-icons/io5";
import classNames from 'classnames';
import { useDashboards } from "utils/hooks/useDashboards";

export const DashboardLinks = ({ session }) => {
  const { dashboards = [], isLoading, error, mutate } = useDashboards();
  const pathname = usePathname();
  const router = useRouter();

  const sensors = useSensors(
    useSensor(PointerSensor),
    useSensor(TouchSensor)
  );


  const onDragEnd = (event) => {
    const { active, over } = event;
    if (over && active.id !== over.id) {
      const oldIndex = dashboards.findIndex(dashboard => dashboard.id === active.id);
      const newIndex = dashboards.findIndex(dashboard => dashboard.id === over.id);
      const newDashboards = arrayMove(dashboards, oldIndex, newIndex);
      mutate(newDashboards, false);
    }
  };

  const deleteDashboard = async (id: string) => {
    const isDeleteConfirmed = confirm('You are about to delete this dashboard. Are you sure?');
    if (isDeleteConfirmed) {
      try {
        const apiUrl = getApiURL();
        await fetch(`${apiUrl}/dashboard/${id}`, {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${session.accessToken}`
          }
        });
        mutate(dashboards.filter(dashboard => dashboard.id !== id), false);
      } catch (error) {
        console.error('Error deleting dashboard:', error);
      }
    }
  };

  const generateUniqueName = (baseName: string): string => {
    let uniqueName = baseName;
    let counter = 1;
    while (dashboards.some(d => d.dashboard_name.toLowerCase() === uniqueName.toLowerCase())) {
      uniqueName = `${baseName}(${counter})`;
      counter++;
    }
    return uniqueName;
  };

  const handleCreateDashboard = () => {
    const uniqueName = generateUniqueName('My Dashboard');
    router.push(`/dashboard/${encodeURIComponent(uniqueName)}`);
  };

  return (
    <Disclosure as="div" className="space-y-1" defaultOpen>
      <Disclosure.Button className="w-full flex justify-between items-center p-2">
        {({ open }) => (
          <>
            <div className="flex justify-between items-center w-full">
              <Subtitle className="text-xs ml-2 text-gray-900 font-medium uppercase">
                Dashboards
              </Subtitle>
              <div className="flex items-center">
                <Badge size="xs" className="mr-1" color="orange">
                  <p className="ml-1">Beta</p>
                </Badge>
                <IoChevronUp className={classNames({ "rotate-180": open }, "mr-2 text-slate-400")} />
              </div>
            </div>
          </>
        )}
      </Disclosure.Button>
      <Disclosure.Panel as="ul" className="space-y-2 overflow-auto min-w-[max-content] p-2 pr-4">
        <DndContext sensors={sensors} collisionDetection={rectIntersection} onDragEnd={onDragEnd}>
          <SortableContext items={dashboards.map(dashboard => dashboard.id)}>
            {dashboards.map((dashboard) => (
              <DashboardLink key={dashboard.id} dashboard={dashboard} pathname={pathname} deleteDashboard={deleteDashboard} />
            ))}
            <li className="flex justify-center">
              <Button size="xs" color="orange" variant="secondary" onClick={handleCreateDashboard}>
                +
              </Button>
            </li>
          </SortableContext>
        </DndContext>
      </Disclosure.Panel>
    </Disclosure>
  );
};
