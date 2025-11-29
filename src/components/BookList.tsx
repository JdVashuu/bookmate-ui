import BookCard from "./BookCard";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface Book {
  id: string;
  title: string;
  author: string;
  genre: string;
  rating: number;
  description: string;
  likes: number;
  created_at: string;
}

interface BookListProps {
  books: Book[];
  sortBy: string;
  onSortChange: (sort: string) => void;
  onLike: (id: string) => void;
}

const BookList = ({ books, sortBy, onSortChange, onLike }: BookListProps) => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-foreground">
          Book Recommendations ({books.length})
        </h2>
        <Select value={sortBy} onValueChange={onSortChange}>
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="Sort by..." />
          </SelectTrigger>
          <SelectContent className="bg-popover">
            <SelectItem value="latest">Sort by Latest</SelectItem>
            <SelectItem value="oldest">Sort by Oldest</SelectItem>
            <SelectItem value="most-liked">Sort by Most Liked</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {books.length === 0 ? (
        <div className="flex min-h-[300px] items-center justify-center rounded-lg border-2 border-dashed border-border bg-muted/30">
          <p className="text-center text-muted-foreground">
            No books found. Add your first recommendation!
          </p>
        </div>
      ) : (
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {books.map((book) => (
            <BookCard key={book.id} book={book} onLike={onLike} />
          ))}
        </div>
      )}
    </div>
  );
};

export default BookList;
