const { JSDOM } = require('jsdom');
const axios = require('axios');

// Function to fetch the HTML content from a URL and print the content
async function fetchAndPrintContent() {
  try {
    // Fetch the HTML of example.com
    const response = await axios.get('https://www.google.ca/search?q=golden+puppy');
    
    // Create a JSDOM instance using the fetched HTML
    const dom = new JSDOM(response.data);

    // Access the content of the page (for example, the entire body content)
    const bodyContent = dom.window.document.body.innerHTML;

    // Print the content of the body
    console.log(bodyContent);
  } catch (error) {
    console.error('Error fetching the page:', error);
  }
}

// Call the function to fetch and print the content of example.com
fetchAndPrintContent();

