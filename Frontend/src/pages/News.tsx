import { useEffect, useState } from "react";
import { Card } from "@/components/ui/card";
import { Layout } from "@/components/Layout";
import { API_BASE_URL } from "@/lib/api";

interface NewsArticle {
  category: string;
  headline: string;
  source: string;
}

export default function News() {
  const [news, setNews] = useState<NewsArticle[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchNews() {
      try {
        const response = await fetch(`${API_BASE_URL}/market-news`);
        if (!response.ok) throw new Error("Failed to fetch news");

        const data = await response.json();
        setNews(data); // ✅ Flask returns an array directly
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
    <Layout>
      <h1 className="text-3xl font-bold mb-6">Financial News & Insights</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {news.map((article, index) => (
          <Card
            key={index}
            className="p-4 hover:shadow-lg transition-all"
          >
            <h3 className="text-lg font-semibold mb-2">{article.headline}</h3>
            <p className="text-sm text-muted-foreground mb-1">
              Category: {article.category}
            </p>
            <p className="text-xs text-muted-foreground">
              Source: {article.source}
            </p>
          </Card>
        ))}
      </div>
    </Layout>
  );
}
