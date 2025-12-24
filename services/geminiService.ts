
import { GoogleGenAI, Type } from "@google/genai";
import { Asset, Threat } from "../types";

// Always use const ai = new GoogleGenAI({apiKey: process.env.API_KEY});
const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

export const analyzeThreatIntelligence = async (assets: Asset[], rawThreatFeed: string[]): Promise<Threat[]> => {
  const modelName = 'gemini-3-flash-preview';
  
  const prompt = `
    Analyze the following raw threat intelligence snippets against a list of corporate assets.
    
    Assets: ${JSON.stringify(assets)}
    Threat Feed: ${rawThreatFeed.join("\n")}

    Identify specific threats that match the technologies used in the assets.
    For each identified threat, provide:
    1. A title and description.
    2. A severity (Low, Medium, High, Critical).
    3. The specific technology targeted.
    4. An 'impactModifier' (a multiplier from 1.0 to 10.0 representing how much this increases the likelihood of an attack on that specific technology).
  `;

  try {
    const response = await ai.models.generateContent({
      model: modelName,
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.ARRAY,
          items: {
            type: Type.OBJECT,
            properties: {
              id: { type: Type.STRING },
              title: { type: Type.STRING },
              description: { type: Type.STRING },
              severity: { type: Type.STRING },
              targetTechnology: { type: Type.STRING },
              impactModifier: { type: Type.NUMBER },
              timestamp: { type: Type.STRING }
            },
            required: ["id", "title", "description", "severity", "targetTechnology", "impactModifier", "timestamp"]
          }
        }
      }
    });

    // The GenerateContentResponse features a text property that directly returns the string output.
    const text = response.text;
    return JSON.parse(text || "[]");
  } catch (error) {
    console.error("Gemini AI Analysis Error:", error);
    return [];
  }
};
