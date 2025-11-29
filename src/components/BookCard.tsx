import { Heart, Star } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface BookCardProps {
  book: {
    id: string;
    title: string;
    author: string;
    genre: string;
    rating: number;
    description: string;
    likes: number;
    created_at: string;
  };
  onLike: (id: string) => void;
}

const BookCard = ({ book, onLike }: BookCardProps) => {
  const truncateText = (text: string, maxLength: number) => {
    if (text.length <= maxLength) return text;
    return text.slice(0, maxLength) + "...";
  };

  const isRecent = () => {
    const addedAt = new Date(book.created_at);
    const daysSinceAdded = Math.floor(
      (Date.now() - addedAt.getTime()) / (1000 * 60 * 60 * 24)
    );
    return daysSinceAdded <= 3;
  };

  return (
    <Card className="group flex h-full flex-col overflow-hidden bg-card shadow-soft transition-smooth hover:shadow-hover">
      <div className="flex-1 p-6">
        <div className="mb-3 flex items-start justify-between gap-2">
          <h3 className="flex-1 text-lg font-semibold leading-tight text-foreground">
            {book.title}
          </h3>
          {isRecent() && (
            <Badge variant="secondary" className="shrink-0 text-xs">
              📅 New
            </Badge>
          )}
        </div>

        <p className="mb-3 text-sm text-muted-foreground">by {book.author}</p>

        <div className="mb-4 flex items-center gap-2">
          <Badge variant="outline" className="text-xs">
            {book.genre}
          </Badge>
          <div className="flex">
            {Array.from({ length: 5 }).map((_, i) => (
              <Star
                key={i}
                className={`h-4 w-4 ${
                  i < book.rating
                    ? "fill-primary text-primary"
                    : "text-muted-foreground"
                }`}
              />
            ))}
          </div>
        </div>

        <p className="text-sm leading-relaxed text-foreground">
          {truncateText(book.description, 150)}
        </p>
      </div>

      <div className="border-t border-border bg-muted/30 px-6 py-3">
        <Button
          onClick={() => onLike(book.id)}
          variant="ghost"
          size="sm"
          className="gap-2 transition-smooth hover:text-primary"
        >
          <Heart className="h-4 w-4" />
          <span className="text-sm font-medium">{book.likes}</span>
        </Button>
      </div>
    </Card>
  );
};

export default BookCard;
