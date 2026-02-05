import { getSortedPostsData, PostData } from "@/lib/posts";
import PostCard from "@/components/PostCard";
import styles from "./page.module.css";

export default function Home() {
  const allPostsData = getSortedPostsData();

  // Filter posts
  const writeups = allPostsData.filter(post => post.title.toLowerCase().includes("writeups"));
  const blogs = allPostsData.filter(post => !post.title.toLowerCase().includes("writeups"));

  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <h1 className={styles.title}>Welcome</h1>
        <p className={styles.subtitle}>
          Exploring Reverse Engineering, CTFs, and Low-Level Magic.
        </p>
      </header>

      {/* Writeups Section */}
      {writeups.length > 0 && (
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>
            CTF Writeups
            <span className={styles.latestMarker}>Latest 3</span>
          </h2>
          <div className={styles.grid}>
            {writeups.slice(0, 3).map((post) => (
              <PostCard
                key={post.id}
                id={post.id}
                title={post.title}
                date={post.date}
                excerpt={post.description || post.excerpt}
                coverImage={post.coverImage}
              />
            ))}
          </div>
        </section>
      )}

      {/* Blogs Section */}
      {blogs.length > 0 && (
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>
            Blog Posts
            <span className={styles.latestMarker}>Latest 3</span>
          </h2>
          <div className={styles.grid}>
            {blogs.slice(0, 3).map((post) => (
              <PostCard
                key={post.id}
                id={post.id}
                title={post.title}
                date={post.date}
                excerpt={post.description || post.excerpt}
                coverImage={post.coverImage}
              />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
