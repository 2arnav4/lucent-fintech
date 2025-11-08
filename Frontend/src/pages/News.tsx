import { useEffect, useState } from "react";
import { Card } from "@/components/ui/card";

interface NewsArticle {
  id: string;
  title: string;
  description: string;
  source: string;
  publishedAt: string;
  url: string;
  imageUrl?: string;
}

export default function News() {  // ✅ Default export added
  const [news, setNews] = useState<NewsArticle[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchNews() {
      try {
        const response = await fetch("/api/news");
        if (!response.ok) throw new Error("Failed to fetch news");
        const data = await response.json();
        setNews(data.articles || []);
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    fetchNews();
  }, []);

  if (loading) return <p className="p-8 text-center text-muted-foreground">Loading news...</p>;
  if (error) return <p className="p-8 text-center text-destructive">{error}</p>;

  return (
    <div className="p-8">
      <h1 className="text-3xl font-bold mb-6">Financial News & Insights</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {news.map((article) => (
          <Card
            key={article.id}
            className="flex flex-col overflow-hidden hover:shadow-lg transition-all"
          >
            {article.imageUrl && (
              <img
                src={article.imageUrl}
                alt={article.title}
                className="h-48 w-full object-cover"
              />
            )}
            <div className="p-4 flex flex-col flex-grow">
              <div className="flex justify-between items-center mb-2">
                <span className="text-xs text-muted-foreground">{article.source}</span>
                <span className="text-xs text-muted-foreground">
                  {new Date(article.publishedAt).toLocaleDateString()}
                </span>
              </div>
              <h3 className="text-lg font-semibold mb-2">{article.title}</h3>
              <p className="text-sm text-muted-foreground flex-grow">
                {article.description || "No description available."}
              </p>
              <a
                href={article.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary mt-3 text-sm hover:underline"
              >
                Read more →
              </a>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
