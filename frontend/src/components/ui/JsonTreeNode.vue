<script setup lang="ts">
import { ChevronRight } from 'lucide-vue-next'
import { inject, type Ref } from 'vue'

const props = defineProps<{
  nodeKey: string
  value: unknown
  path: string
  depth?: number
}>()

const maxDepth = props.depth ?? 20

// Inject shared state from parent
const expandedNodes = inject<Ref<Set<string>>>('jsonExpandedNodes')

const isExpanded = () => expandedNodes?.value.has(props.path) ?? false

const toggle = () => {
  if (!expandedNodes) return
  if (expandedNodes.value.has(props.path)) {
    expandedNodes.value.delete(props.path)
  } else {
    expandedNodes.value.add(props.path)
  }
}

const isObject = (val: unknown): val is Record<string, unknown> => {
  return val !== null && typeof val === 'object'
}

const getItemLabel = (val: unknown): string => {
  if (val === null) return 'null'
  if (Array.isArray(val)) return `[] ${val.length} items`
  if (typeof val === 'object') return `{} ${Object.keys(val).length} items`
  return String(val)
}

const formatValue = (val: unknown): string => {
  if (val === null) return 'null'
  if (typeof val === 'string') return `"${val}"`
  return String(val)
}
</script>

<template>
  <div class="py-0.5">
    <!-- Object/Array - Collapsible -->
    <template v-if="isObject(value)">
      <button 
        @click="toggle"
        class="flex items-center gap-1.5 hover:bg-muted/50 rounded px-1 -ml-1 text-left py-0.5 w-full"
      >
        <ChevronRight 
          class="w-3 h-3 text-muted-foreground transition-transform shrink-0"
          :class="{ 'rotate-90': isExpanded() }" 
        />
        <span class="text-foreground">{{ nodeKey }}:</span>
        <span class="text-muted-foreground">{{ getItemLabel(value) }}</span>
      </button>
      
      <!-- Children -->
      <div 
        v-if="isExpanded() && depth < maxDepth" 
        class="pl-4 border-l border-border/40 ml-1.5 mt-0.5"
      >
        <JsonTreeNode
          v-for="(childVal, childKey) in value"
          :key="`${path}.${childKey}`"
          :node-key="String(childKey)"
          :value="childVal"
          :path="`${path}.${childKey}`"
          :depth="depth + 1"
        />
      </div>
      
      <!-- Max depth reached - show JSON -->
      <div 
        v-else-if="isExpanded() && depth >= maxDepth" 
        class="pl-4 border-l border-border/40 ml-1.5 mt-0.5"
      >
        <pre class="text-foreground whitespace-pre-wrap break-words text-xs">{{ JSON.stringify(value, null, 2) }}</pre>
      </div>
    </template>
    
    <!-- Simple value -->
    <template v-else>
      <div class="flex items-start gap-1.5 pl-4">
        <span class="text-foreground shrink-0">{{ nodeKey }}:</span>
        <span class="text-muted-foreground ml-1 break-all">{{ formatValue(value) }}</span>
      </div>
    </template>
  </div>
</template>
