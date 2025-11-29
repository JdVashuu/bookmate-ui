import { useState, useEffect, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import Header from "@/components/Header";
import RandomBookCard from "@/components/RandomBookCard";
import SearchFilterBar from "@/components/SearchFilterBar";
import AddBookForm from "@/components/AddBookForm";
import BookList from "@/components/BookList";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { User, Session } from "@supabase/supabase-js";

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

const Index = () => {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [books, setBooks] = useState<Book[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedGenre, setSelectedGenre] = useState("All");
  const [sortBy, setSortBy] = useState("latest");
  const [randomBook, setRandomBook] = useState<Book | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const { toast } = useToast();

  useEffect(() => {
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (_event, session) => {
        setSession(session);
        setUser(session?.user ?? null);
      }
    );

    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
    });

    return () => subscription.unsubscribe();
  }, []);

  useEffect(() => {
    if (session) {
      fetchBooks();
    } else {
      setLoading(false);
    }
  }, [session]);

  const fetchBooks = async () => {
    setLoading(true);
    const { data, error } = await supabase
      .from("books")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) {
      toast({
        variant: "destructive",
        title: "Error loading books",
        description: error.message,
      });
    } else {
      setBooks(data || []);
      if (data && data.length > 0) {
        setRandomBook(data[Math.floor(Math.random() * data.length)]);
      }
    }
    setLoading(false);
  };

  const handleAddBook = async (newBook: Omit<Book, "id" | "likes" | "created_at">) => {
    if (!user) {
      toast({
        variant: "destructive",
        title: "Authentication required",
        description: "Please sign in to add books.",
      });
      navigate("/auth");
      return;
    }

    const { error } = await supabase.from("books").insert([
      {
        title: newBook.title,
        author: newBook.author,
        genre: newBook.genre,
        rating: newBook.rating,
        description: newBook.description,
        user_id: user.id,
      },
    ]);

    if (error) {
      toast({
        variant: "destructive",
        title: "Error adding book",
        description: error.message,
      });
    } else {
      toast({
        title: "Book added!",
        description: "Your book recommendation has been added.",
      });
      fetchBooks();
    }
  };

  const handleLike = async (bookId: string) => {
    if (!user) {
      toast({
        variant: "destructive",
        title: "Authentication required",
        description: "Please sign in to like books.",
      });
      navigate("/auth");
      return;
    }

    // Check if already liked
    const { data: existingLike } = await supabase
      .from("book_likes")
      .select("*")
      .eq("book_id", bookId)
      .eq("user_id", user.id)
      .maybeSingle();

    if (existingLike) {
      // Unlike
      await supabase
        .from("book_likes")
        .delete()
        .eq("book_id", bookId)
        .eq("user_id", user.id);

      // Decrement likes count
      const book = books.find(b => b.id === bookId);
      if (book) {
        await supabase
          .from("books")
          .update({ likes: Math.max(0, book.likes - 1) })
          .eq("id", bookId);
      }
    } else {
      // Like
      await supabase.from("book_likes").insert([
        {
          book_id: bookId,
          user_id: user.id,
        },
      ]);

      // Increment likes count
      const book = books.find(b => b.id === bookId);
      if (book) {
        await supabase
          .from("books")
          .update({ likes: book.likes + 1 })
          .eq("id", bookId);
      }
    }

    fetchBooks();
  };

  const handleRefreshRandom = () => {
    if (books.length > 0) {
      const randomIndex = Math.floor(Math.random() * books.length);
      setRandomBook(books[randomIndex]);
    }
  };

  const filteredAndSortedBooks = useMemo(() => {
    let filtered = books;

    // Filter by search
    if (searchQuery) {
      filtered = filtered.filter(
        (book) =>
          book.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
          book.author.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }

    // Filter by genre
    if (selectedGenre !== "All") {
      filtered = filtered.filter((book) => book.genre === selectedGenre);
    }

    // Sort
    const sorted = [...filtered];
    switch (sortBy) {
      case "latest":
        sorted.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
        break;
      case "oldest":
        sorted.sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
        break;
      case "most-liked":
        sorted.sort((a, b) => b.likes - a.likes);
        break;
    }

    return sorted;
  }, [books, searchQuery, selectedGenre, sortBy]);

  if (!session) {
    return (
      <div className="min-h-screen bg-background">
        <Header />
        <main className="container mx-auto px-4 py-16 text-center">
          <h2 className="text-3xl font-bold text-foreground mb-4">
            Welcome to BookMate!
          </h2>
          <p className="text-muted-foreground mb-8 max-w-md mx-auto">
            Sign in to start adding and discovering book recommendations.
          </p>
        </main>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <p className="text-muted-foreground">Loading books...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <Header />
      
      <main className="container mx-auto px-4 py-8">
        <div className="space-y-8">
          {/* Random Book Section */}
          {randomBook && (
            <section>
              <RandomBookCard book={randomBook} onRefresh={handleRefreshRandom} />
            </section>
          )}

          {/* Search and Filter */}
          <section>
            <SearchFilterBar
              searchQuery={searchQuery}
              selectedGenre={selectedGenre}
              onSearchChange={setSearchQuery}
              onGenreChange={setSelectedGenre}
            />
          </section>

          {/* Add Book Form */}
          <section>
            <AddBookForm onAddBook={handleAddBook} />
          </section>

          {/* Book List */}
          <section>
            <BookList
              books={filteredAndSortedBooks}
              sortBy={sortBy}
              onSortChange={setSortBy}
              onLike={(title) => {
                const book = books.find((b) => b.title === title);
                if (book) handleLike(book.id);
              }}
            />
          </section>
        </div>
      </main>
    </div>
  );
};

export default Index;
