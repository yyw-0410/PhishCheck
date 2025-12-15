<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted, nextTick, inject } from 'vue'
import { useChatStore } from '@/stores/chat'
import { useAnalysisStore } from '@/stores/analysis'
import { useAuthStore } from '@/stores/auth'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from '@/components/ui/resizable'
import {
  MessageCircle,
  Send,
  X,
  Maximize2,
  Minimize2,
  Bot,
  User,
  Sparkles,
  Loader2,
  ChevronLeft,
  FileSearch,
  MessageSquarePlus,
} from 'lucide-vue-next'

const emit = defineEmits<{
  expand: [expanded: boolean, width: number]
}>()

const chatStore = useChatStore()
const analysisStore = useAnalysisStore()
const authStore = useAuthStore()

// Check if user is authenticated
const isAuthenticated = computed(() => authStore.isAuthenticated)

// AI status tracking
const aiStatus = ref<'online' | 'offline' | 'checking'>('checking')

// Check AI availability
const checkAiStatus = async () => {
  try {
    const response = await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/api/v1/ai/suggestions`, {
      method: 'GET',
      signal: AbortSignal.timeout(5000) // 5 second timeout
    })
    aiStatus.value = response.ok ? 'online' : 'offline'
  } catch {
    aiStatus.value = 'offline'
  }
}

// Watch for errors to update status
watch(() => chatStore.error, (err) => {
  if (err) aiStatus.value = 'offline'
})

// Watch for successful AI responses to update status to online
watch(() => chatStore.isLoading, (loading, wasLoading) => {
  // When loading finishes (true -> false) and no error, AI is online
  if (wasLoading && !loading && !chatStore.error) {
    aiStatus.value = 'online'
  }
})

// Check if there's an active analysis (any type: email, link, or file)
const hasAnalysis = computed(() => analysisStore.hasAnyAnalysis)

// Auto-switch mode based on analysis availability
watch(hasAnalysis, (has) => {
  chatStore.chatMode = has ? 'analysis' : 'general'
}, { immediate: true })

// UI state
const isOpen = ref(false)
const isExpanded = ref(false)
const userInput = ref('')
const messagesContainer = ref<HTMLElement | null>(null)
const expandedMessagesContainer = ref<HTMLElement | null>(null)

// Resizable state
const panelSize = ref(25) // Default 25% of viewport width
const minPanelSize = ref(20) // Minimum 20%
const maxPanelSize = ref(50) // Maximum 50%

// Window dimensions
const windowWidth = ref(window.innerWidth)
const windowHeight = ref(window.innerHeight)

// Mobile detection
const isMobile = computed(() => windowWidth.value < 768)

// Calculate actual pixel width from panel percentage
const panelPixelWidth = computed(() => {
  return Math.round((panelSize.value / 100) * windowWidth.value)
})

// Handle window resize
const handleWindowResize = () => {
  windowWidth.value = window.innerWidth
  windowHeight.value = window.innerHeight
}

// Communicate with FloatingActions wrapper (if present)
const setChatVisible = inject<(visible: boolean) => void>('setChatVisible', () => { })

// Notify wrapper when chat opens/closes
watch([isOpen, isExpanded], ([open, expanded]) => {
  setChatVisible(open || expanded)
}, { immediate: true })

// Toggle small chat window
const toggleChat = () => {
  if (isExpanded.value) {
    // If expanded, collapse first
    isExpanded.value = false
    emit('expand', false, 0)
  } else {
    isOpen.value = !isOpen.value
  }
}

// Expand to full sidebar (or full screen on mobile)
const expandChat = () => {
  isOpen.value = false
  isExpanded.value = true
  if (!isMobile.value) {
    emit('expand', true, panelPixelWidth.value)
  }
}

// Collapse from sidebar
const collapseChat = () => {
  isExpanded.value = false
  isOpen.value = true
  emit('expand', false, 0)
}

// Handle panel resize
const handlePanelResize = (sizes: number[]) => {
  // The chat panel is the second panel, so we need to calculate its size
  if (sizes.length >= 2 && sizes[1] !== undefined) {
    panelSize.value = sizes[1]
    if (isExpanded.value) {
      emit('expand', true, panelPixelWidth.value)
    }
  }
}

// Send message
const sendMessage = async () => {
  const message = userInput.value.trim()
  if (!message || chatStore.isLoading) return

  userInput.value = ''
  await chatStore.sendMessage(message)
  scrollToBottom()
}

// Handle suggested question click
const handleSuggestionClick = async (question: string) => {
  userInput.value = question
  await sendMessage()
}

// Scroll to bottom of messages (both small and expanded containers)
const scrollToBottom = async () => {
  await nextTick()
  if (messagesContainer.value) {
    messagesContainer.value.scrollTop = messagesContainer.value.scrollHeight
  }
  if (expandedMessagesContainer.value) {
    expandedMessagesContainer.value.scrollTop = expandedMessagesContainer.value.scrollHeight
  }
}

// Watch for new messages and content changes (for auto-scroll during typing)
watch(
  () => chatStore.messages,
  () => scrollToBottom(),
  { deep: true }
)

// Watch panel size changes and emit to parent
watch(panelPixelWidth, (newWidth) => {
  if (isExpanded.value) {
    emit('expand', true, newWidth)
  }
})

// Lifecycle
onMounted(() => {
  window.addEventListener('resize', handleWindowResize)
  chatStore.fetchSuggestedQuestions()
  checkAiStatus() // Check AI status on mount
})

onUnmounted(() => {
  window.removeEventListener('resize', handleWindowResize)
})

// Format message content (handle markdown-like formatting)
const formatMessage = (content: string) => {
  return content
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`(.*?)`/g, '<code class="bg-muted px-1 rounded text-sm">$1</code>')
    .replace(/\n/g, '<br>')
}
</script>

<template>
  <!-- Chat Button (only visible when logged in) -->
  <Transition name="button-pop" appear>
    <Button v-if="isAuthenticated && !isOpen && !isExpanded"
      class="h-14 w-14 rounded-full shadow-lg bg-primary hover:bg-primary/90" title="Open AI Chat" @click="toggleChat">
      <MessageCircle class="h-6 w-6" />
    </Button>
  </Transition>

  <!-- Small Chat Window -->
  <Teleport to="body">
    <Transition name="slide-up">
      <Card v-if="isOpen && !isExpanded"
        class="fixed bottom-6 right-6 w-[360px] shadow-2xl z-50 border-border/50 flex flex-col"
        :style="{ height: isMobile ? '70vh' : '480px', maxHeight: '80vh' }">
        <!-- Header -->
        <CardHeader class="pb-3 flex-shrink-0 border-b">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <div class="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center">
                <Bot class="h-4 w-4 text-primary" />
              </div>
              <div>
                <div class="flex items-center gap-1.5">
                  <CardTitle class="text-base">PhishCheck AI</CardTitle>
                  <div class="relative flex h-1.5 w-1.5"
                    :title="aiStatus === 'online' ? 'AI Online' : aiStatus === 'offline' ? 'AI Offline' : 'Checking...'">
                    <span v-if="aiStatus === 'online'"
                      class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span class="relative inline-flex rounded-full h-1.5 w-1.5" :class="{
                      'bg-emerald-500 shadow-[0_0_3px_theme(colors.emerald.500)]': aiStatus === 'online',
                      'bg-red-500 shadow-[0_0_3px_theme(colors.red.500)]': aiStatus === 'offline',
                      'bg-yellow-500 animate-pulse': aiStatus === 'checking'
                    }"></span>
                  </div>
                </div>
                <p class="text-xs text-muted-foreground">Phishing Expert Assistant</p>
              </div>
            </div>
            <div class="flex items-center gap-1">
              <Button variant="ghost" size="icon" class="h-8 w-8" @click="expandChat" title="Expand">
                <Maximize2 class="h-4 w-4" />
              </Button>
              <Button variant="ghost" size="icon" class="h-8 w-8" @click="toggleChat">
                <X class="h-4 w-4" />
              </Button>
            </div>
          </div>
        </CardHeader>

        <!-- Messages -->
        <CardContent class="flex-1 overflow-hidden p-0">
          <div ref="messagesContainer" class="h-full overflow-y-auto p-4 space-y-4">
            <!-- Welcome message if no messages -->
            <div v-if="chatStore.messages.length === 0" class="space-y-4">
              <div class="text-center py-4">
                <div class="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-3">
                  <Sparkles class="h-6 w-6 text-primary" />
                </div>
                <h3 class="font-medium">Welcome to PhishCheck AI</h3>
                <p class="text-sm text-muted-foreground mt-1">
                  Ask me anything about phishing, email security, or online threats.
                </p>
              </div>

              <!-- Suggested Questions -->
              <div v-if="chatStore.currentQuestions.length > 0" class="space-y-2">
                <p class="text-xs text-muted-foreground font-medium">
                  {{ chatStore.chatMode === 'analysis' ? 'Ask about your analysis:' : 'Suggested questions:' }}
                </p>
                <div class="flex flex-wrap gap-2">
                  <Badge v-for="question in chatStore.currentQuestions.slice(0, 4)" :key="question" variant="secondary"
                    class="cursor-pointer hover:bg-secondary/80 text-xs py-1 px-2 whitespace-normal text-left"
                    @click="handleSuggestionClick(question)">
                    {{ question }}
                  </Badge>
                </div>
              </div>
            </div>

            <!-- Messages list -->
            <template v-for="(message, index) in chatStore.messages" :key="index">
              <div :class="[
                'flex gap-2',
                message.role === 'user' ? 'justify-end' : 'justify-start',
              ]">
                <!-- Assistant avatar -->
                <div v-if="message.role === 'assistant'"
                  class="h-7 w-7 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                  <Bot class="h-3.5 w-3.5 text-primary" />
                </div>

                <!-- Message bubble -->
                <div :class="[
                  'rounded-lg px-3 py-2 max-w-[85%] text-sm',
                  message.role === 'user'
                    ? 'bg-primary text-primary-foreground'
                    : 'bg-muted',
                ]">
                  <div v-html="formatMessage(message.content)" />
                </div>


                <!-- User avatar -->
                <div v-if="message.role === 'user'"
                  class="h-7 w-7 rounded-full bg-secondary flex items-center justify-center flex-shrink-0 overflow-hidden">
                  <img v-if="authStore.user?.avatar" :src="authStore.user.avatar" alt="User"
                    class="h-full w-full object-cover" />
                  <User v-else class="h-3.5 w-3.5" />
                </div>
              </div>
            </template>

            <!-- Loading indicator -->
            <div v-if="chatStore.isLoading" class="flex gap-2 justify-start">
              <div class="h-7 w-7 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                <Bot class="h-3.5 w-3.5 text-primary" />
              </div>
              <div class="bg-muted rounded-lg px-3 py-2">
                <Loader2 class="h-4 w-4 animate-spin" />
              </div>
            </div>
          </div>
        </CardContent>

        <!-- Input - Gemini Style -->
        <div class="p-3 border-t flex-shrink-0">
          <div class="bg-muted/50 rounded-2xl border">
            <Input v-model="userInput" placeholder="Ask a question..." :disabled="chatStore.isLoading"
              class="border-0 bg-transparent text-sm focus-visible:ring-0 focus-visible:ring-offset-0"
              @keydown.enter.prevent="sendMessage" />
            <div class="flex items-center justify-between px-3 pb-2">
              <div class="flex items-center gap-1">
                <Button variant="ghost" size="icon" class="h-8 w-8 rounded-full"
                  :class="{ 'bg-primary/10 text-primary': chatStore.chatMode === 'general' }"
                  @click="chatStore.startNewChat()" title="New Chat">
                  <MessageSquarePlus class="h-4 w-4" />
                </Button>
                <Button variant="ghost" size="icon" class="h-8 w-8 rounded-full"
                  :class="{ 'bg-primary/10 text-primary': chatStore.chatMode === 'analysis' }" :disabled="!hasAnalysis"
                  @click="chatStore.startAnalysisChat()" title="Analysis Mode">
                  <FileSearch class="h-4 w-4" />
                </Button>
              </div>
              <Button size="icon" :disabled="!userInput.trim() || chatStore.isLoading" class="h-8 w-8 rounded-full"
                @click="sendMessage">
                <Send class="h-4 w-4" />
              </Button>
            </div>
          </div>
          <p class="text-[10px] text-muted-foreground mt-1.5 text-center">Powered by Gemini · AI can make mistakes</p>
        </div>
      </Card>
    </Transition>
  </Teleport>

  <!-- Mobile Full-Screen Chat -->
  <Teleport to="body">
    <Transition name="slide-up">
      <div v-if="isExpanded && isMobile" class="fixed inset-0 z-50 bg-background flex flex-col">
        <!-- Mobile Header -->
        <div class="flex items-center justify-between p-4 border-b flex-shrink-0">
          <div class="flex items-center gap-3">
            <div class="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center">
              <Bot class="h-5 w-5 text-primary" />
            </div>
            <div>
              <div class="flex items-center gap-1.5">
                <h2 class="font-semibold">PhishCheck AI</h2>
                <div class="relative flex h-1.5 w-1.5"
                  :title="aiStatus === 'online' ? 'AI Online' : aiStatus === 'offline' ? 'AI Offline' : 'Checking...'">
                  <span v-if="aiStatus === 'online'"
                    class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span class="relative inline-flex rounded-full h-1.5 w-1.5" :class="{
                    'bg-emerald-500 shadow-[0_0_3px_theme(colors.emerald.500)]': aiStatus === 'online',
                    'bg-red-500 shadow-[0_0_3px_theme(colors.red.500)]': aiStatus === 'offline',
                    'bg-yellow-500 animate-pulse': aiStatus === 'checking'
                  }"></span>
                </div>
              </div>
              <p class="text-xs text-muted-foreground">Phishing Expert Assistant</p>
            </div>
          </div>
          <Button variant="ghost" size="icon" class="h-9 w-9" @click="collapseChat">
            <X class="h-5 w-5" />
          </Button>
        </div>

        <!-- Mobile Messages -->
        <div class="flex-1 overflow-y-auto p-4 space-y-4">
          <!-- Welcome message if no messages -->
          <div v-if="chatStore.messages.length === 0" class="space-y-6">
            <div class="text-center py-6">
              <div class="h-14 w-14 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4">
                <Sparkles class="h-7 w-7 text-primary" />
              </div>
              <h3 class="text-lg font-medium">Welcome to PhishCheck AI</h3>
              <p class="text-sm text-muted-foreground mt-2">
                Ask me anything about phishing, email security, or online threats.
              </p>
            </div>

            <!-- Suggested Questions -->
            <div v-if="chatStore.currentQuestions.length > 0" class="space-y-3">
              <p class="text-sm text-muted-foreground font-medium">
                {{ chatStore.chatMode === 'analysis' ? 'Ask about your analysis:' : 'Suggested questions:'
                }}
              </p>
              <div class="grid gap-2">
                <Button v-for="question in chatStore.currentQuestions" :key="question" variant="outline"
                  class="justify-start text-left h-auto py-3 px-4 whitespace-normal"
                  @click="handleSuggestionClick(question)">
                  <Sparkles class="h-4 w-4 mr-2 flex-shrink-0 text-primary" />
                  <span class="text-sm">{{ question }}</span>
                </Button>
              </div>
            </div>
          </div>

          <!-- Messages list -->
          <template v-for="(message, index) in chatStore.messages" :key="index">
            <div :class="[
              'flex gap-3',
              message.role === 'user' ? 'justify-end' : 'justify-start',
            ]">
              <div v-if="message.role === 'assistant'"
                class="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                <Bot class="h-4 w-4 text-primary" />
              </div>
              <div :class="[
                'rounded-lg px-4 py-3 max-w-[85%]',
                message.role === 'user'
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-muted',
              ]">
                <div v-html="formatMessage(message.content)" class="text-sm leading-relaxed" />
              </div>
              <div v-if="message.role === 'user'"
                class="h-8 w-8 rounded-full bg-secondary flex items-center justify-center flex-shrink-0 overflow-hidden">
                <img v-if="authStore.user?.avatar" :src="authStore.user.avatar" alt="User"
                  class="h-full w-full object-cover" />
                <User v-else class="h-4 w-4" />
              </div>
            </div>
          </template>

          <!-- Loading indicator -->
          <div v-if="chatStore.isLoading" class="flex gap-3 justify-start">
            <div class="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
              <Bot class="h-4 w-4 text-primary" />
            </div>
            <div class="bg-muted rounded-lg px-4 py-3">
              <Loader2 class="h-5 w-5 animate-spin" />
            </div>
          </div>
        </div>

        <!-- Mobile Input -->
        <div class="p-4 border-t flex-shrink-0 pb-safe">
          <div class="bg-muted/50 rounded-2xl border">
            <Input v-model="userInput" placeholder="Ask a question..." :disabled="chatStore.isLoading"
              class="border-0 bg-transparent focus-visible:ring-0 focus-visible:ring-offset-0"
              @keydown.enter.prevent="sendMessage" />
            <div class="flex items-center justify-between px-3 pb-3">
              <div class="flex items-center gap-1">
                <Button variant="ghost" size="icon" class="h-9 w-9 rounded-full"
                  :class="{ 'bg-primary/10 text-primary': chatStore.chatMode === 'general' }"
                  @click="chatStore.startNewChat()" title="New Chat">
                  <MessageSquarePlus class="h-4 w-4" />
                </Button>
                <Button variant="ghost" size="icon" class="h-9 w-9 rounded-full"
                  :class="{ 'bg-primary/10 text-primary': chatStore.chatMode === 'analysis' }" :disabled="!hasAnalysis"
                  @click="chatStore.startAnalysisChat()" title="Analysis Mode">
                  <FileSearch class="h-4 w-4" />
                </Button>
              </div>
              <Button size="icon" :disabled="!userInput.trim() || chatStore.isLoading" class="h-9 w-9 rounded-full"
                @click="sendMessage">
                <Send class="h-4 w-4" />
              </Button>
            </div>
          </div>
          <p class="text-xs text-muted-foreground mt-2 text-center">Powered by Gemini · AI can make mistakes
          </p>
        </div>
      </div>
    </Transition>
  </Teleport>

  <!-- Expanded Resizable Sidebar (Desktop) -->
  <Teleport to="body">
    <Transition name="slide-in">
      <div v-if="isExpanded && !isMobile" class="fixed inset-0 z-40" style="pointer-events: none;">
        <ResizablePanelGroup direction="horizontal" class="h-full" @layout="handlePanelResize">
          <!-- Spacer Panel (takes remaining space) -->
          <ResizablePanel :default-size="100 - panelSize" :min-size="50" style="pointer-events: none;" />

          <!-- Resize Handle -->
          <ResizableHandle class="w-1 bg-border hover:bg-primary/50 transition-colors cursor-col-resize"
            style="pointer-events: auto;" />

          <!-- Chat Panel -->
          <ResizablePanel :default-size="panelSize" :min-size="minPanelSize" :max-size="maxPanelSize"
            style="pointer-events: auto;">
            <div class="h-full bg-background border-l shadow-xl flex flex-col">
              <!-- Header -->
              <div class="flex items-center justify-between p-4 border-b flex-shrink-0">
                <div class="flex items-center gap-3">
                  <Button variant="ghost" size="icon" class="h-8 w-8" @click="collapseChat" title="Collapse">
                    <ChevronLeft class="h-4 w-4" />
                  </Button>
                  <div class="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center">
                    <Bot class="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <div class="flex items-center gap-1.5">
                      <h2 class="font-semibold">PhishCheck AI</h2>
                      <div class="relative flex h-1.5 w-1.5"
                        :title="aiStatus === 'online' ? 'AI Online' : aiStatus === 'offline' ? 'AI Offline' : 'Checking...'">
                        <span v-if="aiStatus === 'online'"
                          class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                        <span class="relative inline-flex rounded-full h-1.5 w-1.5" :class="{
                          'bg-emerald-500 shadow-[0_0_3px_theme(colors.emerald.500)]': aiStatus === 'online',
                          'bg-red-500 shadow-[0_0_3px_theme(colors.red.500)]': aiStatus === 'offline',
                          'bg-yellow-500 animate-pulse': aiStatus === 'checking'
                        }"></span>
                      </div>
                    </div>
                    <p class="text-xs text-muted-foreground">Phishing Expert Assistant</p>
                  </div>
                </div>
                <Button variant="ghost" size="icon" class="h-8 w-8" @click="collapseChat">
                  <Minimize2 class="h-4 w-4" />
                </Button>
              </div>

              <!-- Messages -->
              <div class="flex-1 overflow-hidden">
                <div ref="expandedMessagesContainer" class="h-full overflow-y-auto">
                  <div class="p-4 space-y-4">
                    <!-- Welcome message if no messages -->
                    <div v-if="chatStore.messages.length === 0" class="space-y-6">
                      <div class="text-center py-8">
                        <div class="h-16 w-16 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4">
                          <Sparkles class="h-8 w-8 text-primary" />
                        </div>
                        <h3 class="text-lg font-medium">Welcome to PhishCheck AI</h3>
                        <p class="text-sm text-muted-foreground mt-2 max-w-sm mx-auto">
                          I'm here to help you understand phishing threats, analyze suspicious emails, and learn
                          about
                          email security best practices.
                        </p>
                      </div>

                      <!-- Suggested Questions -->
                      <div v-if="chatStore.currentQuestions.length > 0" class="space-y-3">
                        <p class="text-sm text-muted-foreground font-medium">
                          {{ chatStore.chatMode === 'analysis' ? 'Ask about your analysis:' : 'Try asking:' }}
                        </p>
                        <div class="grid gap-2">
                          <Button v-for="question in chatStore.currentQuestions" :key="question" variant="outline"
                            class="justify-start text-left h-auto py-3 px-4 whitespace-normal"
                            @click="handleSuggestionClick(question)">
                            <Sparkles class="h-4 w-4 mr-2 flex-shrink-0 text-primary" />
                            <span class="text-sm">{{ question }}</span>
                          </Button>
                        </div>
                      </div>
                    </div>

                    <!-- Messages list -->
                    <template v-for="(message, index) in chatStore.messages" :key="index">
                      <div :class="[
                        'flex gap-3',
                        message.role === 'user' ? 'justify-end' : 'justify-start',
                      ]">
                        <!-- Assistant avatar -->
                        <div v-if="message.role === 'assistant'"
                          class="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                          <Bot class="h-4 w-4 text-primary" />
                        </div>

                        <!-- Message bubble -->
                        <div :class="[
                          'rounded-lg px-4 py-3 max-w-[80%]',
                          message.role === 'user'
                            ? 'bg-primary text-primary-foreground'
                            : 'bg-muted',
                        ]">
                          <div v-html="formatMessage(message.content)" class="text-sm leading-relaxed" />
                        </div>

                        <!-- User avatar -->
                        <div v-if="message.role === 'user'"
                          class="h-8 w-8 rounded-full bg-secondary flex items-center justify-center flex-shrink-0 overflow-hidden">
                          <img v-if="authStore.user?.avatar" :src="authStore.user.avatar" alt="User"
                            class="h-full w-full object-cover" />
                          <User v-else class="h-4 w-4" />
                        </div>
                      </div>
                    </template>

                    <!-- Loading indicator -->
                    <div v-if="chatStore.isLoading" class="flex gap-3 justify-start">
                      <div class="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                        <Bot class="h-4 w-4 text-primary" />
                      </div>
                      <div class="bg-muted rounded-lg px-4 py-3">
                        <Loader2 class="h-5 w-5 animate-spin" />
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Input - Gemini Style -->
              <div class="p-4 border-t flex-shrink-0">
                <div class="bg-muted/50 rounded-2xl border">
                  <Input v-model="userInput" placeholder="Ask a question..." :disabled="chatStore.isLoading"
                    class="border-0 bg-transparent focus-visible:ring-0 focus-visible:ring-offset-0"
                    @keydown.enter.prevent="sendMessage" />
                  <div class="flex items-center justify-between px-3 pb-3">
                    <div class="flex items-center gap-1">
                      <Button variant="ghost" size="icon" class="h-9 w-9 rounded-full"
                        :class="{ 'bg-primary/10 text-primary': chatStore.chatMode === 'general' }"
                        @click="chatStore.startNewChat()" title="New Chat">
                        <MessageSquarePlus class="h-4 w-4" />
                      </Button>
                      <Button variant="ghost" size="icon" class="h-9 w-9 rounded-full"
                        :class="{ 'bg-primary/10 text-primary': chatStore.chatMode === 'analysis' }"
                        :disabled="!hasAnalysis" @click="chatStore.startAnalysisChat()" title="Analysis Mode">
                        <FileSearch class="h-4 w-4" />
                      </Button>
                    </div>
                    <Button size="icon" :disabled="!userInput.trim() || chatStore.isLoading"
                      class="h-9 w-9 rounded-full" @click="sendMessage">
                      <Send class="h-4 w-4" />
                    </Button>
                  </div>
                </div>
                <p class="text-xs text-muted-foreground mt-2 text-center">Powered by Gemini · AI can make mistakes
                </p>
              </div>
            </div>
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
/* Transitions */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

/* Smooth button grow/shrink animation */
.button-pop-enter-active {
  transition: opacity 0.5s ease-out, transform 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
}

.button-pop-leave-active {
  transition: opacity 0.4s ease-in, transform 0.4s ease-in;
}

.button-pop-enter-from {
  opacity: 0;
  transform: scale(0);
}

.button-pop-leave-to {
  opacity: 0;
  transform: scale(0);
}

.slide-up-enter-active,
.slide-up-leave-active {
  transition: all 0.3s ease;
}

.slide-up-enter-from,
.slide-up-leave-to {
  opacity: 0;
  transform: translateY(20px);
}

.slide-in-enter-active,
.slide-in-leave-active {
  transition: all 0.3s ease;
}

.slide-in-enter-from,
.slide-in-leave-to {
  opacity: 0;
  transform: translateX(100%);
}

/* Ensure scrollarea works properly */
:deep(.h-full) {
  height: 100%;
}

/* Fix long URL overflow in chat messages */
:deep(div[v-html]),
:deep(div > br),
:deep(.rounded-lg) {
  word-break: break-word;
  overflow-wrap: break-word;
}

/* Additional fix for code blocks with URLs */
:deep(code) {
  word-break: break-all;
  overflow-wrap: break-word;
}
</style>
