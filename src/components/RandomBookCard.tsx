import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";

interface RandomBookCardProps {
  book: {
    title: string;
    author: string;
    description: string;
    coverUrl?: string;
  };
  onRefresh: () => void;
}

const RandomBookCard = ({ book, onRefresh }: RandomBookCardProps) => {
  return (
    <Card className="overflow-hidden border-2 border-primary/20 bg-card shadow-medium transition-smooth hover:shadow-hover">
      <div className="gradient-warm p-1">
        <div className="bg-card p-6">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-2xl font-bold text-foreground">
              <span>🎲</span>
              Random Book of the Day
            </h2>
            <Button
              onClick={onRefresh}
              variant="outline"
              size="icon"
              className="shrink-0 transition-smooth hover:rotate-180"
            >
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>

          <div className="flex flex-col gap-6 sm:flex-row">
            <div className="flex h-48 w-full items-center justify-center rounded-lg bg-muted sm:w-32 sm:shrink-0">
              {book.coverUrl ? (
                <img
                  src={book.coverUrl}
                  alt={book.title}
                  className="h-full w-full rounded-lg object-cover"
                />
              ) : (
                <BookOpen className="h-16 w-16 text-muted-foreground" />
              )}
            </div>

            <div className="flex-1">
              <h3 className="mb-2 text-xl font-semibold text-foreground">
                {book.title}
              </h3>
              <p className="mb-3 text-sm text-muted-foreground">
                by {book.author}
              </p>
              <p className="text-sm leading-relaxed text-foreground">
                {book.description}
              </p>
            </div>
          </div>
        </div>
      </div>
    </Card>
  );
};

export default RandomBookCard;

const BookOpen = ({ className }: { className?: string }) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    fill="none"
    viewBox="0 0 24 24"
    strokeWidth={1.5}
    stroke="currentColor"
    className={className}
  >
    <path
      strokeLinecap="round"
      strokeLinejoin="round"
      d="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25"
    />
  </svg>
);
