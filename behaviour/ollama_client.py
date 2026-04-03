import ollama
import logging

class OllamaClient:
    """
    A lightweight wrapper for connecting to the local Ollama instance.
    Handles 'Few-Shot Prompting' and generation of deception payloads.
    """
    def __init__(self, model_name="phi3:mini"):
        self.model_name = model_name
        self.logger = logging.getLogger(__name__)

    def is_available(self):
        """Check if the Ollama service and the specific model are available."""
        try:
            # Check if we can connect and if the model is downloaded
            models = ollama.list()
            model_names = [m['name'] for m in models.get('models', [])]
            return any(self.model_name in name for name in model_names)
        except Exception as e:
            self.logger.warning(f"Ollama connection failed: {e}")
            return False

    def pull_model(self):
        """Pull the model from the Ollama registry if it doesn't exist."""
        self.logger.info(f"Downloading {self.model_name}... This might take a while.")
        ollama.pull(self.model_name)
        self.logger.info(f"Model {self.model_name} successfully downloaded!")

    def generate_response(self, prompt, system_prompt=None):
        """Generate a response from the LLM."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": prompt})

        try:
            response = ollama.chat(model=self.model_name, messages=messages)
            return response['message']['content']
        except Exception as e:
            self.logger.error(f"Error generating response from Ollama: {e}")
            return "Connection Timed Out." # Fallback honeypot response
