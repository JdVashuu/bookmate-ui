import { Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

const GENRES = [
  "All",
  "Fiction",
  "Non-fiction",
  "Sci-Fi",
  "Romance",
  "Thriller",
  "Mystery",
];

interface SearchFilterBarProps {
  searchQuery: string;
  selectedGenre: string;
  onSearchChange: (query: string) => void;
  onGenreChange: (genre: string) => void;
}

const SearchFilterBar = ({
  searchQuery,
  selectedGenre,
  onSearchChange,
  onGenreChange,
}: SearchFilterBarProps) => {
  return (
    <div className="space-y-4">
      <div className="relative">
        <Search className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground" />
        <Input
          type="text"
          placeholder="Search by title or author..."
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          className="pl-10 shadow-soft transition-smooth focus:shadow-medium"
        />
      </div>

      <div className="flex flex-wrap gap-2">
        {GENRES.map((genre) => (
          <Button
            key={genre}
            onClick={() => onGenreChange(genre)}
            variant={selectedGenre === genre ? "default" : "outline"}
            size="sm"
            className="rounded-full transition-smooth"
          >
            {genre}
          </Button>
        ))}
      </div>
    </div>
  );
};

export default SearchFilterBar;
