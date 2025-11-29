import { BookOpen } from "lucide-react";

const Header = () => {
  return (
    <header className="border-b border-border bg-card shadow-soft">
      <div className="container mx-auto px-4 py-6">
        <div className="flex items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary">
            <BookOpen className="h-6 w-6 text-primary-foreground" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-foreground">BookMate</h1>
            <p className="text-sm text-muted-foreground">
              Submit books, explore genres, and discover new reads.
            </p>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
