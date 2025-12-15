<script setup lang="ts">
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { 
  ArrowLeft, 
  HelpCircle, 
  Mail, 
  Search,
  FileText,
  Shield,
  User,
  Settings,
  ChevronRight
} from 'lucide-vue-next'
import { useRouter } from 'vue-router'
import { ref, computed } from 'vue'

const router = useRouter()

const goBack = () => {
  router.back()
}

const searchQuery = ref('')
const activeCategory = ref('all')

const categories = [
  { id: 'all', name: 'All Topics', icon: HelpCircle },
  { id: 'getting-started', name: 'Getting Started', icon: FileText },
  { id: 'analysis', name: 'Analysis Tools', icon: Shield },
  { id: 'account', name: 'Account & Billing', icon: User },
  { id: 'technical', name: 'Technical Issues', icon: Settings },
]

const allFaqs = [
  {
    category: 'getting-started',
    question: "What is PhishCheck?",
    answer: "PhishCheck is an advanced email security platform that helps you analyze suspicious emails, check links, and verify sender authentication."
  },
  {
    category: 'getting-started',
    question: "How do I create an account?",
    answer: "Click the 'Sign Up' button in the top right corner. You can register with your email or use Google/Microsoft SSO."
  },
  {
    category: 'analysis',
    question: "How do I analyze a suspicious email?",
    answer: "Navigate to the 'Analyzer' section and upload your .eml or .msg file. Our system will automatically scan headers, body content, and attachments."
  },
  {
    category: 'analysis',
    question: "What file formats are supported?",
    answer: "We currently support .eml (RFC 822) and .msg (Outlook) file formats. For best results, we recommend using .eml files."
  },
  {
    category: 'analysis',
    question: "How accurate is the AI detection?",
    answer: "Our AI provides a probability score based on known phishing patterns. While highly accurate, it should be used as an assistant tool alongside other indicators."
  },
  {
    category: 'account',
    question: "Is my data private?",
    answer: "Yes. Files uploaded for analysis are processed temporarily and then deleted according to our retention policy. We do not sell your data."
  },
  {
    category: 'account',
    question: "How do I reset my password?",
    answer: "If you signed in with Google or Microsoft, use their account recovery. For email accounts, please contact our support team at support@phishcheck.com for assistance."
  },
  {
    category: 'technical',
    question: "The analyzer is stuck on 'Scanning'. What should I do?",
    answer: "This can happen with very large files. Try refreshing the page. If the issue persists, please check your internet connection or try a smaller file."
  },
  {
    category: 'technical',
    question: "Can I use the API?",
    answer: "API access is available for enterprise plans. Please contact our sales team for documentation and access keys."
  }
]

const filteredFaqs = computed(() => {
  let faqs = allFaqs
  
  // Filter by category
  if (activeCategory.value !== 'all') {
    faqs = faqs.filter(faq => faq.category === activeCategory.value)
  }
  
  // Filter by search query
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    faqs = faqs.filter(faq => 
      faq.question.toLowerCase().includes(query) || 
      faq.answer.toLowerCase().includes(query)
    )
  }
  
  return faqs
})
</script>

<template>
  <div class="min-h-screen bg-background">
    <!-- Back Button - Fixed Top Left -->
    <div class="fixed top-4 left-4 z-50">
      <Button variant="ghost" size="sm" class="text-muted-foreground hover:text-foreground" @click="goBack">
        <ArrowLeft class="h-4 w-4 mr-2" />
        Back
      </Button>
    </div>

    <!-- Header Hero -->
    <div class="bg-muted/30 border-b">
      <div class="container max-w-6xl mx-auto py-12 px-4 pt-16">
        <div class="text-center max-w-2xl mx-auto mb-8">
          <h1 class="text-3xl md:text-4xl font-bold tracking-tight mb-4">How can we help you?</h1>
          <p class="text-muted-foreground text-lg mb-8">Search our knowledge base or browse topics below.</p>
          
          <div class="relative">
            <Search class="absolute left-3 top-3 h-5 w-5 text-muted-foreground" />
            <Input 
              v-model="searchQuery"
              class="pl-10 h-12 text-lg bg-background shadow-sm" 
              placeholder="Search for answers (e.g., 'how to analyze email')" 
            />
          </div>
        </div>
      </div>
    </div>

    <div class="container max-w-6xl mx-auto py-12 px-4">
      
      <!-- Categories -->
      <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-12">
        <button
          v-for="category in categories"
          :key="category.id"
          @click="activeCategory = category.id"
          class="flex flex-col items-center justify-center p-4 rounded-xl border transition-all hover:border-primary hover:bg-primary/5"
          :class="activeCategory === category.id ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'bg-card'"
        >
          <component :is="category.icon" class="h-6 w-6 mb-2" :class="activeCategory === category.id ? 'text-primary' : 'text-muted-foreground'" />
          <span class="text-sm font-medium" :class="activeCategory === category.id ? 'text-foreground' : 'text-muted-foreground'">{{ category.name }}</span>
        </button>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-12 gap-10">
        
        <!-- FAQ List -->
        <div class="lg:col-span-8 space-y-6">
          <div v-if="filteredFaqs.length === 0" class="text-center py-12 border rounded-lg bg-muted/10">
            <HelpCircle class="h-12 w-12 text-muted-foreground mx-auto mb-4 opacity-50" />
            <h3 class="text-lg font-medium">No results found</h3>
            <p class="text-muted-foreground">Try adjusting your search or browse all topics.</p>
            <Button variant="link" @click="searchQuery = ''; activeCategory = 'all'" class="mt-2">
              Clear filters
            </Button>
          </div>

          <div v-else class="space-y-4">
            <Card v-for="(faq, index) in filteredFaqs" :key="index" class="overflow-hidden transition-all hover:shadow-md">
              <CardHeader class="pb-3 cursor-pointer">
                <CardTitle class="text-lg flex items-start justify-between gap-4">
                  {{ faq.question }}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p class="text-muted-foreground leading-relaxed">{{ faq.answer }}</p>
              </CardContent>
            </Card>
          </div>
        </div>

        <!-- Sidebar Info -->
        <div class="lg:col-span-4 space-y-6">
          <!-- Contact Card -->
          <Card class="bg-primary/5 border-primary/10">
            <CardHeader>
              <CardTitle class="flex items-center gap-2">
                <Mail class="h-5 w-5 text-primary" />
                Still need help?
              </CardTitle>
              <CardDescription>
                Can't find the answer you're looking for? Our team is here to assist you.
              </CardDescription>
            </CardHeader>
            <CardContent class="space-y-4">
              <Button class="w-full" @click="router.push('/feedback')">
                Contact Support
              </Button>
              <div class="text-center text-xs text-muted-foreground">
                or email us at <a href="mailto:support@phishcheck.com" class="underline hover:text-primary">support@phishcheck.com</a>
              </div>
            </CardContent>
          </Card>

          <!-- Quick Links -->
          <Card>
            <CardHeader>
              <CardTitle class="text-base">Quick Links</CardTitle>
            </CardHeader>
            <CardContent class="p-0">
              <div class="flex flex-col">
                <button @click="router.push('/terms')" class="flex items-center justify-between p-4 hover:bg-muted/50 transition-colors border-b last:border-0 text-sm">
                  <span>Terms of Service</span>
                  <ChevronRight class="h-4 w-4 text-muted-foreground" />
                </button>
                <button @click="router.push('/privacy')" class="flex items-center justify-between p-4 hover:bg-muted/50 transition-colors border-b last:border-0 text-sm">
                  <span>Privacy Policy</span>
                  <ChevronRight class="h-4 w-4 text-muted-foreground" />
                </button>
              </div>
            </CardContent>
          </Card>
        </div>

      </div>
    </div>
  </div>
</template>
