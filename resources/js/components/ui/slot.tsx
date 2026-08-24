import { useRender } from "@base-ui/react/use-render"
import * as React from "react"

interface SlotProps extends React.HTMLAttributes<HTMLElement> {
  children?: React.ReactNode
}

function Slot({ children, ...props }: SlotProps) {
  return useRender<Record<string, never>, HTMLElement>({
    defaultTagName: "span",
    props,
    render: React.isValidElement(children) ? children : undefined,
  })
}

export { Slot }
