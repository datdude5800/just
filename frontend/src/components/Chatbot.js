import { useState } from 'react';
import axios from 'axios';
import { MessageCircle, X, Send, Loader2 } from 'lucide-react';
import { toast } from 'sonner';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

const Chatbot = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([
    {
      role: 'bot',
      content: 'Hi! I\'m SecCheck AI Assistant. How can I help you today?',
      suggestions: ['What services do you offer?', 'Show me pricing', 'How does this work?']
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [sessionId, setSessionId] = useState(null);

  const sendMessage = async (text) => {
    if (!text.trim() && !input.trim()) return;

    const messageText = text || input;
    
    // Add user message
    setMessages(prev => [...prev, { role: 'user', content: messageText }]);
    setInput('');
    setLoading(true);

    try {
      const response = await axios.post(`${BACKEND_URL}/api/chatbot/message`, {
        message: messageText,
        session_id: sessionId
      });

      setSessionId(response.data.session_id);
      
      // Add bot response
      setMessages(prev => [...prev, {
        role: 'bot',
        content: response.data.response,
        suggestions: response.data.suggestions
      }]);
    } catch (error) {
      toast.error('Chat error: ' + (error.response?.data?.detail || error.message));
      setMessages(prev => [...prev, {
        role: 'bot',
        content: 'Sorry, I encountered an error. Please try again.'
      }]);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    sendMessage();
  };

  return (
    <>
      {/* Chat Button */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="fixed bottom-6 right-6 w-16 h-16 bg-[#0055FF] text-white rounded-full shadow-lg flex items-center justify-center hover:bg-[#0044DD] transition-all z-50"
          data-testid="chatbot-open-btn"
        >
          <MessageCircle className="w-8 h-8" />
        </button>
      )}

      {/* Chat Window */}
      {isOpen && (
        <div className="fixed bottom-6 right-6 w-96 h-[600px] bg-white border-2 border-[#E4E4E7] shadow-2xl flex flex-col z-50"
             data-testid="chatbot-window">
          {/* Header */}
          <div className="bg-[#0055FF] text-white p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <MessageCircle className="w-6 h-6" />
              <div>
                <div className="font-heading font-black text-lg">SecCheck AI</div>
                <div className="text-xs text-white/80">Customer Service</div>
              </div>
            </div>
            <button
              onClick={() => setIsOpen(false)}
              className="hover:bg-white/20 p-2 transition-colors"
              data-testid="chatbot-close-btn"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-[#F4F4F5]">
            {messages.map((msg, idx) => (
              <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[80%] ${
                  msg.role === 'user' 
                    ? 'bg-[#0055FF] text-white' 
                    : 'bg-white text-[#09090B] border border-[#E4E4E7]'
                } p-3 text-sm font-body whitespace-pre-wrap`}>
                  {msg.content}
                  
                  {/* Suggestions */}
                  {msg.suggestions && msg.role === 'bot' && (
                    <div className="mt-3 space-y-2">
                      {msg.suggestions.map((suggestion, i) => (
                        <button
                          key={i}
                          onClick={() => sendMessage(suggestion)}
                          className="block w-full text-left px-3 py-2 bg-[#F4F4F5] hover:bg-[#E4E4E7] text-[#09090B] text-xs transition-colors"
                        >
                          {suggestion}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
            
            {loading && (
              <div className="flex justify-start">
                <div className="bg-white border border-[#E4E4E7] p-3 flex items-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin text-[#0055FF]" />
                  <span className="text-sm text-[#71717A]">Typing...</span>
                </div>
              </div>
            )}
          </div>

          {/* Input */}
          <form onSubmit={handleSubmit} className="p-4 border-t border-[#E4E4E7] bg-white">
            <div className="flex gap-2">
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Type your message..."
                className="flex-1 px-4 py-2 border border-[#E4E4E7] bg-[#F4F4F5]/30 font-body text-sm focus:outline-none focus:border-[#0055FF]"
                data-testid="chatbot-input"
                disabled={loading}
              />
              <button
                type="submit"
                disabled={loading || !input.trim()}
                className="px-4 py-2 bg-[#0055FF] text-white hover:bg-[#0044DD] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                data-testid="chatbot-send-btn"
              >
                <Send className="w-5 h-5" />
              </button>
            </div>
          </form>
        </div>
      )}
    </>
  );
};

export default Chatbot;
