<script setup lang="ts">
import { ref, onMounted, nextTick, computed } from 'vue'
import DOMPurify from 'dompurify'
import { useChatStore } from '@/stores/chat'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'

const chatStore = useChatStore()
const inputMessage = ref('')
const chatContainer = ref<HTMLElement | null>(null)

// Scroll to bottom when new messages arrive
const scrollToBottom = async () => {
  await nextTick()
  if (chatContainer.value) {
    chatContainer.value.scrollTop = chatContainer.value.scrollHeight
  }
}

// Send message handler
const handleSend = async () => {
  if (!inputMessage.value.trim() || chatStore.isLoading) return

  const message = inputMessage.value
  inputMessage.value = ''

  await chatStore.sendMessage(message)
  scrollToBottom()
}

// Handle suggested question click
const handleSuggestionClick = async (question: string) => {
  inputMessage.value = question
  await handleSend()
}

// Handle enter key
const handleKeyPress = (event: KeyboardEvent) => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault()
    handleSend()
  }
}

// Format message content with markdown-like styling
const formatContent = (content: string) => {
  // Convert **bold** to <strong>
  let formatted = content.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
  // Convert bullet points
  formatted = formatted.replace(/^- (.+)$/gm, '<li>$1</li>')
  // Convert numbered lists
  formatted = formatted.replace(/^\d+\. (.+)$/gm, '<li>$1</li>')
  // Convert line breaks
  formatted = formatted.replace(/\n\n/g, '</p><p>')
  formatted = formatted.replace(/\n/g, '<br>')
  // Sanitize to prevent XSS
  return DOMPurify.sanitize(`<p>${formatted}</p>`, { ALLOWED_TAGS: ['p', 'br', 'strong', 'li', 'ul', 'ol'] })
}

onMounted(() => {
  chatStore.fetchSuggestedQuestions()
})
</script>

<template>
  <div class="flex flex-col h-full max-h-[calc(100vh-4rem)] p-4">
    <!-- Header -->
    <div class="mb-4">
      <h1 class="text-2xl font-bold text-foreground">PhishCheck AI Assistant</h1>
      <p class="text-muted-foreground">
        Ask me anything about phishing, email security, and cybersecurity
      </p>
    </div>

    <!-- Chat Container -->
    <Card class="flex-1 flex flex-col min-h-0 overflow-hidden">
      <CardHeader class="border-b flex-shrink-0 py-3">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <div class="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-primary" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" stroke-width="2">
                <path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8z" />
                <path d="M12 6v6l4 2" />
              </svg>
            </div>
            <div>
              <CardTitle class="text-base">PhishCheck AI</CardTitle>
              <CardDescription class="text-xs">Phishing & Security Expert</CardDescription>
            </div>
          </div>
          <Button v-if="chatStore.hasMessages" variant="ghost" size="sm" @click="chatStore.clearChat()">
            Clear Chat
          </Button>
        </div>
      </CardHeader>

      <CardContent ref="chatContainer" class="flex-1 overflow-y-auto p-4 space-y-4">
        <!-- Welcome message when no messages -->
        <div v-if="!chatStore.hasMessages" class="flex flex-col items-center justify-center h-full text-center">
          <div class="h-16 w-16 rounded-full bg-primary/10 flex items-center justify-center mb-4">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8 text-primary" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10" />
              <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
              <path d="M12 17h.01" />
            </svg>
          </div>
          <h3 class="text-lg font-semibold mb-2">How can I help you today?</h3>
          <p class="text-muted-foreground mb-6 max-w-md">
            I'm your phishing and email security expert. Ask me about identifying phishing attempts,
            email authentication, or what to do if you've been targeted.
          </p>

          <!-- Suggested Questions -->
          <div class="w-full max-w-2xl">
            <p class="text-sm text-muted-foreground mb-3">Try asking:</p>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <Button v-for="question in chatStore.suggestedQuestions.slice(0, 6)" :key="question" variant="outline"
                size="sm" class="justify-start text-left h-auto py-2 px-3 whitespace-normal"
                @click="handleSuggestionClick(question)">
                {{ question }}
              </Button>
            </div>
          </div>
        </div>

        <!-- Messages -->
        <template v-else>
          <div v-for="message in chatStore.messages" :key="message.id" class="flex gap-3"
            :class="message.role === 'user' ? 'justify-end' : 'justify-start'">
            <!-- Avatar for assistant -->
            <div v-if="message.role === 'assistant'"
              class="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-primary" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10" />
                <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
                <path d="M12 17h.01" />
              </svg>
            </div>

            <!-- Message bubble -->
            <div class="max-w-[80%] rounded-lg px-4 py-2" :class="message.role === 'user'
              ? 'bg-primary text-primary-foreground'
              : 'bg-muted'">
              <div v-if="message.role === 'assistant'" class="prose prose-sm dark:prose-invert max-w-none"
                v-html="formatContent(message.content)" />
              <p v-else>{{ message.content }}</p>

              <!-- Sources -->
              <div v-if="message.sources && message.sources.length > 0" class="mt-2 pt-2 border-t border-border/50">
                <p class="text-xs text-muted-foreground mb-1">Sources:</p>
                <div class="flex flex-wrap gap-1">
                  <Badge v-for="source in message.sources" :key="source.id" variant="secondary" class="text-xs">
                    {{ source.title }}
                  </Badge>
                </div>
              </div>
            </div>

            <!-- Avatar for user -->
            <div v-if="message.role === 'user'"
              class="h-8 w-8 rounded-full bg-primary flex items-center justify-center flex-shrink-0">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-primary-foreground" viewBox="0 0 24 24"
                fill="none" stroke="currentColor" stroke-width="2">
                <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" />
                <circle cx="12" cy="7" r="4" />
              </svg>
            </div>
          </div>

          <!-- Loading indicator -->
          <div v-if="chatStore.isLoading" class="flex gap-3 justify-start">
            <div class="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-primary animate-spin" viewBox="0 0 24 24"
                fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 12a9 9 0 1 1-6.219-8.56" />
              </svg>
            </div>
            <div class="bg-muted rounded-lg px-4 py-2">
              <div class="flex items-center gap-1">
                <span class="w-2 h-2 bg-primary/60 rounded-full animate-bounce" style="animation-delay: 0ms"></span>
                <span class="w-2 h-2 bg-primary/60 rounded-full animate-bounce" style="animation-delay: 150ms"></span>
                <span class="w-2 h-2 bg-primary/60 rounded-full animate-bounce" style="animation-delay: 300ms"></span>
              </div>
            </div>
          </div>
        </template>
      </CardContent>

      <!-- Input area -->
      <div class="border-t p-4 flex-shrink-0">
        <form @submit.prevent="handleSend" class="flex gap-2">
          <Input v-model="inputMessage" placeholder="Ask about phishing, email security..." class="flex-1"
            :disabled="chatStore.isLoading" @keypress="handleKeyPress" />
          <Button type="submit" :disabled="!inputMessage.trim() || chatStore.isLoading">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" stroke-width="2">
              <path d="m22 2-7 20-4-9-9-4Z" />
              <path d="M22 2 11 13" />
            </svg>
            <span class="ml-2 hidden sm:inline">Send</span>
          </Button>
        </form>
        <p class="text-xs text-muted-foreground mt-2 text-center">
          PhishCheck AI uses a knowledge base about phishing. Responses are for educational purposes.
        </p>
      </div>
    </Card>
  </div>
</template>

<style scoped>
/* Ensure proper scrolling in the chat container */
.overflow-y-auto {
  scrollbar-width: thin;
  scrollbar-color: hsl(var(--border)) transparent;
}

.overflow-y-auto::-webkit-scrollbar {
  width: 6px;
}

.overflow-y-auto::-webkit-scrollbar-track {
  background: transparent;
}

.overflow-y-auto::-webkit-scrollbar-thumb {
  background-color: hsl(var(--border));
  border-radius: 3px;
}

/* Prose styles for markdown content */
.prose :deep(p) {
  margin-bottom: 0.5rem;
}

.prose :deep(li) {
  margin-left: 1rem;
  list-style-type: disc;
}

.prose :deep(strong) {
  font-weight: 600;
}
</style>
