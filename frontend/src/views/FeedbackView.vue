<script setup lang="ts">
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { 
  ArrowLeft, 
  Send, 
  Bug, 
  Lightbulb, 
  CheckCircle2,
  Mail
} from 'lucide-vue-next'
import { useRouter } from 'vue-router'
import { ref } from 'vue'

const router = useRouter()

const goBack = () => {
  router.back()
}

const form = ref({
  name: '',
  email: '',
  subject: 'feedback',
  message: ''
})

const pageTitle = 'Feedback & Suggestions'
const pageDescription = 'We value your input! Let us know how we can improve PhishCheck.'

const isSubmitting = ref(false)
const isSuccess = ref(false)

const submitForm = async () => {
  isSubmitting.value = true
  // Simulate API call
  await new Promise(resolve => setTimeout(resolve, 1500))
  isSubmitting.value = false
  isSuccess.value = true
  
  // Reset form after success
  setTimeout(() => {
    isSuccess.value = false
    form.value = {
      name: '',
      email: '',
      subject: 'feedback',
      message: ''
    }
  }, 3000)
}

const faqs = [
  {
    question: "How do you use my feedback?",
    answer: "We review all suggestions weekly to plan our roadmap. Your input directly influences new features."
  },
  {
    question: "Can I request a specific integration?",
    answer: "Absolutely! Let us know which security tools you use, and we'll investigate adding them."
  },
  {
    question: "Do you offer a bug bounty?",
    answer: "Not currently, but we appreciate responsible disclosure of any security issues you find."
  }
]
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
        <div class="flex flex-col md:flex-row md:items-center gap-6">
          <div class="h-16 w-16 rounded-2xl bg-primary/10 flex items-center justify-center shrink-0">
            <Lightbulb class="h-8 w-8 text-primary" />
          </div>
          <div>
            <h1 class="text-3xl md:text-4xl font-bold tracking-tight mb-2">{{ pageTitle }}</h1>
            <p class="text-muted-foreground text-lg">{{ pageDescription }}</p>
          </div>
        </div>
      </div>
    </div>

    <div class="container max-w-6xl mx-auto py-12 px-4">
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-10">
        
        <!-- Contact Form -->
        <div class="lg:col-span-7 space-y-8">
          <Card>
            <CardHeader>
              <CardTitle>Share your thoughts</CardTitle>
              <CardDescription>
                Have an idea or found a bug? We'd love to hear from you.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form @submit.prevent="submitForm" class="space-y-6">
                <div class="grid sm:grid-cols-2 gap-4">
                  <div class="space-y-2">
                    <Label for="name">Name</Label>
                    <Input id="name" v-model="form.name" placeholder="Your name" required />
                  </div>
                  <div class="space-y-2">
                    <Label for="email">Email</Label>
                    <Input id="email" type="email" v-model="form.email" placeholder="your@email.com" required />
                  </div>
                </div>

                <div class="space-y-2">
                  <Label for="subject">Type</Label>
                  <div class="grid grid-cols-2 gap-4">
                    <div 
                      class="border rounded-lg p-4 flex flex-col items-center text-center gap-2 cursor-pointer transition-all"
                      :class="form.subject === 'feedback' ? 'bg-primary/5 border-primary ring-1 ring-primary' : 'hover:bg-muted/50'"
                      @click="form.subject = 'feedback'"
                    >
                      <Lightbulb class="h-5 w-5" :class="form.subject === 'feedback' ? 'text-primary' : 'text-muted-foreground'" />
                      <span class="text-sm font-medium">Feature Idea</span>
                    </div>
                    <div 
                      class="border rounded-lg p-4 flex flex-col items-center text-center gap-2 cursor-pointer transition-all"
                      :class="form.subject === 'bug' ? 'bg-primary/5 border-primary ring-1 ring-primary' : 'hover:bg-muted/50'"
                      @click="form.subject = 'bug'"
                    >
                      <Bug class="h-5 w-5" :class="form.subject === 'bug' ? 'text-primary' : 'text-muted-foreground'" />
                      <span class="text-sm font-medium">Report Bug</span>
                    </div>
                  </div>
                </div>

                <div v-if="form.subject === 'bug'" class="space-y-2">
                  <Label for="steps">Steps to Reproduce</Label>
                  <textarea 
                    id="steps" 
                    class="flex min-h-[100px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 resize-y"
                    placeholder="1. Go to...&#10;2. Click on...&#10;3. See error..."
                  ></textarea>
                </div>

                <div class="space-y-2">
                  <Label for="message">
                    {{ form.subject === 'feedback' ? 'Your Suggestion' : 'Bug Description' }}
                  </Label>
                  <textarea 
                    id="message" 
                    v-model="form.message"
                    class="flex min-h-[150px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 resize-y"
                    placeholder="Tell us more..."
                    required
                  ></textarea>
                </div>

                <Button type="submit" class="w-full" :disabled="isSubmitting || isSuccess">
                  <template v-if="isSuccess">
                    <CheckCircle2 class="mr-2 h-4 w-4" />
                    Sent!
                  </template>
                  <template v-else-if="isSubmitting">
                    <span class="animate-spin mr-2">⏳</span>
                    Sending...
                  </template>
                  <template v-else>
                    <Send class="mr-2 h-4 w-4" />
                    Send Feedback
                  </template>
                </Button>
              </form>
            </CardContent>
          </Card>
        </div>

        <!-- Sidebar Info -->
        <div class="lg:col-span-5 space-y-8">
          <!-- Quick Contact Info -->
          <Card class="bg-primary/5 border-primary/10">
            <CardContent class="p-6">
              <h3 class="font-semibold mb-4 flex items-center gap-2">
                <Mail class="h-5 w-5 text-primary" />
                Direct Contact
              </h3>
              <p class="text-sm text-muted-foreground mb-4">
                Prefer email? You can send your feedback directly to:
              </p>
              <a href="mailto:feedback@phishcheck.com" class="text-primary hover:underline font-medium">
                feedback@phishcheck.com
              </a>
            </CardContent>
          </Card>

          <!-- FAQ Section -->
          <div>
            <h3 class="text-lg font-semibold mb-4 flex items-center gap-2">
              <Lightbulb class="h-5 w-5 text-primary" />
              Common Questions
            </h3>
            <div class="space-y-4">
              <div v-for="(faq, index) in faqs" :key="index" class="bg-card border rounded-lg p-4">
                <h4 class="font-medium text-sm mb-2">{{ faq.question }}</h4>
                <p class="text-sm text-muted-foreground leading-relaxed">{{ faq.answer }}</p>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  </div>
</template>
